import { log } from './logger';
import { Stack } from './stack';
// Script to gather the shared library from disk and also
// from memory utilizing Frida. After reading the file from
// disk, it will then compare some sections of the file in
// order to hunt and identify potentially modified and hooked
// functions.
//
// Re-written over the ages for usage while
// unpacking Android applications by
// Tim 'diff' Strazzere <diff -at- protonmail.com>
// Based off older code and concepts from lich4/lichao890427

// Helper function for creating a native function for usage
function getNativeFunction(
  name: string,
  ret: NativeFunctionReturnType,
  args: NativeFunctionArgumentType[],
): NativeFunction<any, any> {
  const mod = Module.findExportByName(null, name);
  if (!mod) {
    throw new Error(`Unable to location module ${name}`);
  }

  const func = new NativeFunction(mod, ret, args);
  if (typeof func === 'undefined') {
    throw Error(`Unable to create the NativeFunction for ${name} using ${ret} and ${args}`);
  }

  return func;
}

const openPtr = getNativeFunction('open', 'int', ['pointer', 'int', 'int']);
const readPtr = getNativeFunction('read', 'int', ['int', 'pointer', 'int']);
const closePtr = getNativeFunction('close', 'int', ['int']);
const lseekPtr = getNativeFunction('lseek', 'int', ['int', 'int', 'int']);

type Section = {
  name: string;
  memoryOffset: number;
  fileOffset: number;
  size: number;
  data: NativePointer | undefined;
};

type ElfData = {
  is32: boolean;
  sections: Section[];
  symbols: string[];
  relmap: Map<number, number> | undefined;
};

function getElfData(module: Module): ElfData | undefined {
  const elfData: ElfData = {
    is32: false,
    sections: [],
    symbols: [],
    relmap: undefined,
  };
  const fd = openPtr(Memory.allocUtf8String(module.path), 0 /* O_RDONLY */, 0);
  if (fd === -1) {
    return undefined;
  }

  // Get elf header
  const header = Memory.alloc(64);
  lseekPtr(fd, 0, 0 /* SEEK_SET */);
  readPtr(fd, header, 64);

  // Allow for both 32bit and 64bit binaries
  const is32 = header.add(4).readU8() === 1;
  elfData.is32 = is32;

  // Parse section headers
  const sectionHeaderOffset = is32 ? header.add(32).readU32() : header.add(40).readU64().toNumber(); // For some reason this is read as a string
  const sectionHeaderSize = is32 ? header.add(46).readU16() : header.add(58).readU16();
  const sectionHeaderCount = is32 ? header.add(48).readU16() : header.add(60).readU16();
  const sectionHeaderStringTableIndex = is32 ? header.add(50).readU16() : header.add(62).readU16();

  const sectionHeaders = Memory.alloc(sectionHeaderSize * sectionHeaderCount);

  lseekPtr(fd, sectionHeaderOffset, 0 /* SEEK_SET */);
  readPtr(fd, sectionHeaders, sectionHeaderSize * sectionHeaderCount);

  const stringTableOffset = is32
    ? sectionHeaders.add(sectionHeaderSize * sectionHeaderStringTableIndex + 16).readU32()
    : sectionHeaders
        .add(sectionHeaderSize * sectionHeaderStringTableIndex + 24)
        .readU64()
        .toNumber();
  const stringTableSize = is32
    ? sectionHeaders.add(sectionHeaderSize * sectionHeaderStringTableIndex + 20).readU32()
    : sectionHeaders
        .add(sectionHeaderSize * sectionHeaderStringTableIndex + 32)
        .readU64()
        .toNumber();

  const stringTable = Memory.alloc(stringTableSize);
  lseekPtr(fd, stringTableOffset, 0 /* SEEK_SET */);
  readPtr(fd, stringTable, stringTableSize);

  for (let i = 0; i < sectionHeaderCount; i++) {
    let sectionName = stringTable
      .add(sectionHeaders.add(i * sectionHeaderSize).readU32())
      .readUtf8String();
    if (!sectionName) {
      sectionName = 'unknown';
    }
    const sectionAddress = is32
      ? sectionHeaders.add(i * sectionHeaderSize + 12).readU32()
      : sectionHeaders
          .add(i * sectionHeaderSize + 16)
          .readU64()
          .toNumber();
    const sectionOffset = is32
      ? sectionHeaders.add(i * sectionHeaderSize + 16).readU32()
      : sectionHeaders
          .add(i * sectionHeaderSize + 24)
          .readU64()
          .toNumber();
    const sectionSize = is32
      ? sectionHeaders.add(i * sectionHeaderSize + 20).readU32()
      : sectionHeaders
          .add(i * sectionHeaderSize + 32)
          .readU64()
          .toNumber();

    const section: Section = {
      name: sectionName,
      memoryOffset: sectionAddress,
      fileOffset: sectionOffset,
      size: sectionSize,
      data: undefined,
    };
    if (sectionSize > 0) {
      section.data = Memory.alloc(sectionSize);
      lseekPtr(fd, sectionOffset, 0 /* SEEK_SET */);
      readPtr(fd, section.data, sectionSize);
    } else {
      section.data = undefined;
    }

    elfData.sections.push(section);
  }

  const dynsym = elfData.sections.filter((section) => section.name === '.dynsym')[0];
  const dynstr = elfData.sections.filter((section) => section.name === '.dynstr')[0];

  if (dynsym && dynstr) {
    const stringTable = module.base.add(dynstr.memoryOffset);
    const structSize = is32 ? 16 : 24;
    for (let i = 0; i < dynsym.size / structSize; i++) {
      const symbolOffset = module.base.add(dynsym.memoryOffset + structSize * i).readU32();
      const symbolString = stringTable.add(symbolOffset).readUtf8String();
      if (symbolString) {
        elfData.symbols.push(symbolString);
      }
    }
  }

  const reldyn = elfData.sections.filter((section) => section.name === '.reldyn')[0];
  elfData.relmap = new Map();
  if (reldyn) {
    for (let i = 0; i < reldyn.size / 8; i++) {
      const key = module.base.add(reldyn.memoryOffset + i * 8).readU32();
      const value = module.base.add(reldyn.memoryOffset + i * 8 + 4).readU32() >> 8;
      if (key !== 0 && value !== 0) {
        elfData.relmap.set(key, value);
      }
    }
  }

  const relplt = elfData.sections.filter((section) => section.name === '.relplt')[0];
  if (relplt) {
    for (let i = 0; i < relplt.size / 8; i++) {
      const key = module.base.add(relplt.memoryOffset + i * 8).readU32();
      const value = module.base.add(relplt.memoryOffset + i * 8 + 4).readU32() >> 8;
      if (key !== 0 && value !== 0) {
        elfData.relmap.set(key, value);
      }
    }
  }

  return elfData;
}

export function findHooks(module: Module) {
  const elfData = getElfData(module);
  if (!elfData) {
    return;
  }

  const hookableSections = elfData.sections.filter((section) =>
    ['.rodata', '.text'].includes(section.name),
  );

  hookableSections.forEach((section) => {
    if (section === undefined || section.data === undefined || section.size === 0) {
      return;
    }

    // It's important to cast the ArrayBuffer returned by `readByteArray` cannot be referenced incrementally
    const sectionBuffer = section.data.readByteArray(section.size);
    if (!sectionBuffer) {
      return;
    }
    const file = new Uint8Array(sectionBuffer);
    const memoryBuffer = module.base.add(section.memoryOffset).readByteArray(section.size);
    if (!memoryBuffer) {
      return;
    }
    const memory = new Uint8Array(memoryBuffer);
    let start = -1;
    let end = 0;
    for (let i = 0; i < section.size; i++) {
      if (file[i] !== memory[i]) {
        if (start === -1) {
          start = i;
        }
      } else {
        if (start !== -1) {
          end = i - 1;

          try {
            const instruction = Instruction.parse(
              module.base.add(section.memoryOffset).add(start),
            ) as Arm64Instruction;
            log(`[!] Potential variance found that is ${end - start} bytes long;`);

            if (['ldr'].includes(instruction.mnemonic)) {
              const trampoline = new NativePointer(
                instruction.operands[1].value as number,
              ).readPointer();
              log(
                `${DebugSymbol.fromAddress(
                  module.base.add(section.memoryOffset).add(start),
                )} => ${Stack.getModuleInfo(trampoline)}`,
              );
            } else {
              log(`${DebugSymbol.fromAddress(module.base.add(section.memoryOffset).add(start))} `);
            }

            const instruction2 = Instruction.parse(instruction.next);
            i += instruction.size + instruction2.size;
            log(` > ${instruction.toString()}`);
            log(` > ${instruction2.toString()}`);

            log(
              hexdump(module.base.add(section.memoryOffset).add(start), {
                offset: 0,
                length: 30, //end - start + 1,
                header: true,
                ansi: true,
              }),
            );
          } catch (error) {
            log('Unable to parse instructions');
          }
          start = -1;
        }
      }
    }
  });
}

// Quick and simple way to get the package name, assumes that the script
// was injected into an APK otherwise it won't work.
function getPackageName() {
  const cmdLine = Memory.allocUtf8String('/proc/self/cmdline');
  const fd = openPtr(cmdLine, 0 /* O_RDONLY */, 0);
  if (fd === -1) {
    return 'null';
  }

  const buffer = Memory.alloc(32);
  readPtr(fd, buffer, 32);
  closePtr(fd);

  return buffer.readUtf8String();
}

// Adjust this as needed, often I don't need to scan anything outside of the
// included shared libraries and a few which are almost always in an apex folder.
// This logic will need to be changed if you're using a pre-apex version of Android
// to ensure it picked up the proper libraries for hunting
//
// While it doesn't hurt to scan everything, it's almost never needed and will just slow
// down the process at a linear scale.
//
// If you already know what you're hunting for, feel free to just return or look for
// libart, libdvm, etc, etc
function getRelevantModules() {
  const packageName = getPackageName();

  if (!packageName) {
    throw Error(`Unable to get package name, cannot determine what is relevant`);
  }

  return Process.enumerateModules().reduce((relevant, module) => {
    if (module.path.includes(packageName) || module.path.includes(`/apex`)) {
      relevant.push(module);
      log(`Adding ${module.path}`);
    } else {
      log(`Skipping ${module.path}`);
    }

    return relevant;
  }, [] as Module[]);
}

export function processRelevantModules() {
  getRelevantModules().forEach((module) => {
    findHooks(module);
  });
}
