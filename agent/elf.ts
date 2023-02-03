import { log } from './logger';
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
function getNativeFunction(name: string, ret, args): NativeFunction<any, any> {
  var mod = Module.findExportByName(null, name);
  if (!mod) {
    throw new Error(`Unable to location module ${name}`);
  }

  var func = new NativeFunction(mod, ret, args);
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
  log('Processing ', module.path);

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
  var header = Memory.alloc(64);
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

  for (var i = 0; i < sectionHeaderCount; i++) {
    let sectionName = stringTable
      .add(sectionHeaders.add(i * sectionHeaderSize).readU32())
      .readUtf8String();
    if (!sectionName) {
      sectionName = 'none';
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
      log('No data section for', section.name);
      section.data = undefined;
    }

    elfData.sections.push(section);
  }

  let dynsym = elfData.sections.filter((section) => section.name === '.dynsym').at(0);
  let dynstr = elfData.sections.filter((section) => section.name === '.dynstr').at(0);

  if (dynsym && dynstr) {
    let stringTable = module.base.add(dynstr.memoryOffset);
    let structSize = is32 ? 16 : 24;
    for (var i = 0; i < dynsym.size / structSize; i++) {
      var symbolOffset = module.base
        .add(dynsym.memoryOffset)
        .add(structSize * i)
        .readU32();
      let symbolString = stringTable.add(symbolOffset).readUtf8String();
      if (symbolString) {
        elfData.symbols.push(symbolString);
      }
    }
  }

  let reldyn = elfData.sections.filter((section) => section.name === '.reldyn').at(0);
  elfData.relmap = new Map();
  if (reldyn) {
    for (var i = 0; i < reldyn.size / 8; i++) {
      if (
        module.base
          .add(reldyn.memoryOffset)
          .add(i * 8)
          .readU32() !== 0 &&
        module.base
          .add(reldyn.memoryOffset)
          .add(i * 8)
          .add(4)
          .readU32() >>
          8 !==
          0
      ) {
        elfData.relmap[
          module.base
            .add(reldyn.memoryOffset)
            .add(i * 8)
            .readU32()
        ] =
          module.base
            .add(reldyn.memoryOffset)
            .add(i * 8)
            .add(4)
            .readU32() >> 8;
      }
    }
  }

  let relplt = elfData.sections.filter((section) => section.name === '.relplt').at(0);
  if (relplt) {
    for (var i = 0; i < relplt.size / 8; i++) {
      if (
        module.base
          .add(relplt.memoryOffset)
          .add(i * 8)
          .readU32() !== 0 &&
        module.base
          .add(relplt.memoryOffset)
          .add(i * 8)
          .add(4)
          .readU32() >>
          8 !==
          0
      ) {
        elfData.relmap[
          module.base
            .add(relplt.memoryOffset)
            .add(i * 8)
            .readU32()
        ] =
          module.base
            .add(relplt.memoryOffset)
            .add(i * 8)
            .add(4)
            .readU32() >> 8;
      }
    }
  }

  return elfData;
}

export function findHooks(module) {
  if (module.sections === undefined) {
    if (!getElfData(module)) {
      return undefined;
    }
  }

  module.sections.forEach((section) => {
    if (section.size === 0) {
      return;
    }

    // It's important to cast the ArrayBuffer returned by `readByteArray` cannot be referenced incrementally

    var file = new Uint8Array(section.data.readByteArray(section.size));
    var memory = new Uint8Array(module.base.add(section.memoryOffset).readByteArray(section.size));
    for (var i = 0; i < section.size; ) {
      if (['.rodata', '.text'].includes(section.name)) {
        if (file[i] != memory[i]) {
          log(
            '*** Potential variance found at ',
            DebugSymbol.fromAddress(module.base.add(section.memoryOffset).add(i)),
          );
          i += 4;
        }
        i++;
      } else if (['.got'].includes(section.name)) {
        break;
        // It shouldn't be as the got table isn't initialized until execution
        if (file[i] != memory[i]) {
          // todo compare the symbol to string against what it resolves too
        }
        i += module.is32 ? 4 : 8;
      } else {
        // Unscanned sections, to be added as needed
        break;
      }
    }
  });
}

// Quick and simple way to get the package name, assumes that the script
// was injected into an APK otherwise it won't work.
function getPackageName() {
  const cmdLine = Memory.allocUtf8String('/proc/self/cmdline');
  var fd = openPtr(cmdLine, 0 /* O_RDONLY */, 0);
  if (fd == -1) {
    return 'null';
  }

  var buffer = Memory.alloc(32);
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
    getElfData(module);
    findHooks(module);
  });
}
