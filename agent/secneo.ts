import { log } from './logger.js';
import { Stack } from './stack.js';
import { getPackageName, writeDexToFile } from './dex.js';
import { NeedleMap } from './needle.js';

const targetLibrary = 'libDexHelper.so';
const debug = false;
let dexBase: NativePointer;
let cLoader: Java.Wrapper<object>;

const needleMap = new NeedleMap();

function getDexBase(): NativePointer {
  const base = Module.findBaseAddress(targetLibrary);
  if (!base) {
    throw new Error(`Unable to get base address for ${targetLibrary}`);
  }

  return base;
}

export function secneoJavaHooks() {
  // Java.deoptimizeEverything();
  Java.perform(function () {
    log(` [*] Removing analytics and privacy services via java hooks`);
    // Don't load analytics to avoid libmsaoaidsec.so from being loaded, plus who cares about analytics
    // Lcom/dji/component/application/DJIPrimaryServiceBuilder;->a(Landroid/app/Application;)V;
    const DJIPrimaryServiceBuilder = Java.use(
      `com.dji.component.application.DJIPrimaryServiceBuilder`,
    );
    DJIPrimaryServiceBuilder.a.overload('android.app.Application').implementation = function (
      _application: Java.Wrapper<object>,
    ) {
      log(` [!] Skipping DJIPrimaryServiceBuilder.a(application)  (skip analytics injection)`);
    };

    // Skip "STEP_ONE" of StartUpActivity which tries to start the privacy service we want to avoid
    const startUpActivityOrderEnum = Java.use(
      `com.dji.component.application.util.DJILaunchUtil$StartUpActivityOrder`,
    );
    const DJILaunchUtil = Java.use(`com.dji.component.application.util.DJILaunchUtil`);
    DJILaunchUtil.handleAppStartUp.overload(
      `android.content.Context`,
      `com.dji.component.application.util.DJILaunchUtil$StartUpActivityOrder`,
    ).implementation = function (
      context: Java.Wrapper<object>,
      startUpActivityOrder: Java.Wrapper<object>,
    ) {
      if (debug) {
        log(`startUpActivityOrder was : ${startUpActivityOrder.toString()}`);
      }
      // change it to STEP_TWO
      startUpActivityOrder = startUpActivityOrderEnum.$new().b.value;
      if (debug) {
        log(`startUpActivityOrder is : ${startUpActivityOrder.toString()}`);
      }

      this.handleAppStartUp(context, startUpActivityOrder);
    };
  });
}

function catchAndUseClassLoader(callback: (classLoader: Java.Wrapper<object>) => void) {
  Java.performNow(() => {
    const dexclassLoader = Java.use('dalvik.system.DexClassLoader');
    dexclassLoader.loadClass.overload('java.lang.String').implementation = function (name: string) {
      const result = this.loadClass(name, false);
      if (!cLoader) {
        // eslint-disable-next-line @typescript-eslint/no-this-alias
        cLoader = this;
        callback(cLoader);
      }

      return result;
    };
  });
}

export function forceLoadClasses() {
  const packagename = getPackageName();

  if (packagename && !packagename.includes('pilot')) {
    // We know this works fine for Fly, so just retain the logic
    catchAndUseClassLoader((classLoader) => {
      log('  [+] Classloader found, attempting to load classes now!');
      // Load these now incase the class loader object for some reason dies -- which does happen (removed likely)
      loadClasses(classLoader);
    });
  } else {
    // This appears to always be present in secneo stubs, so we can use this to locate the correct classloader
    const knownSecNeoClass = 'com/secneo/apkwrapper/AW';
    let classLoaders = Java.enumerateClassLoadersSync();

    classLoaders = classLoaders.filter((classLoader) => {
      try {
        classLoader.loadClass(knownSecNeoClass, false);
        return true;
      } catch (_error) {
        return false;
      }
    });

    if (classLoaders.length === 0) {
      log(` [!] Unable to find a classloader used be SecNeo`);
    } else if (classLoaders.length > 1) {
      log(
        ` [!] Found an abnormal amount of classloaders which may work, defaulting to first found...`,
      );
    }

    loadClasses(classLoaders[0]);
  }
}

function loadClasses(classLoader: Java.Wrapper<object>) {
  let loaded = 0;
  let errorLoading = 0;

  Java.performNow(function () {
    if (classLoader !== null) {
      let classesToLoad: string[] = [];
      const neededClasses = getNeededClasses();
      if (neededClasses && neededClasses.length > 0) {
        classesToLoad = classesToLoad.concat(neededClasses);
      }

      log(`  [+] Attempting to force load ${classesToLoad.length} classes`);
      classesToLoad.forEach((clazz) => {
        try {
          // Resolving or not doesn't seem to matter
          // Don't resolve
          // classLoader.loadClass(clazz, false);
          // Force resolve
          classLoader.loadClass(clazz, true);
          loaded++;
          if (loaded % 1000 == 0) {
            log(` [+] Have caught at least ${loaded} functions so far...`);
          }
        } catch (error) {
          errorLoading++;
          log(` [-] Skipping errored class : ${clazz} : ${error}`);
        }
      });
    } else {
      log(`[!] No classloader found, unable to forceload classes`);
    }
  });
  log(`  [*] Done hunting loaded classes`);
  log(`   [*] Loaded : ${loaded}`);
  if (errorLoading > 0) {
    log(`   [!] errorLoading : ${errorLoading}`);
  } else {
    needleMap.close();
  }
}

export function dumpDexFiles() {
  // LOAD:0000000000031684 ; __int64 __fastcall expandedv2data(char *p, int, int *)
  // LOAD:0000000000031684                 EXPORT _Z14expandedv2dataPciPi
  // (0x6E9B299684 - 0x6E9B268000).toString(16) = 0x31684
  const _Z14expandedv2dataPciPi = Module.findExportByName(targetLibrary, `_Z14expandedv2dataPciPi`);
  // const _Z14expandedv2dataPciPi = dexBase.add(0x031684);
  if (_Z14expandedv2dataPciPi) {
    log('[*] _Z14expandedv2dataPciPi : ', _Z14expandedv2dataPciPi);
    Interceptor.attach(_Z14expandedv2dataPciPi, {
      onEnter: function (args) {
        this.args0 = args[0];
        log(
          `Hit _Z14expandedv2dataPciPi : "${args[0].readUtf8String()}" : ${
            args[1]
          } : ${args[2].readU32()}`,
        );
        // This is the decrypted and decompressed payload from inside the classes.dgc, so write it to disk
        // this still have missing bytes from the functions though
        writeDexToFile(args[0]);
        log(Stack.native(this.context));
      },
      onLeave: function (_retval) {
        // At the return it isn't actually going to be fixed, annoyingly
        // so nothing to do here, as we already captured the output we want
      },
    });
  }

  // Not needed but this is related to the above:
  // 00000000000CE44C                 EXPORT zipOpen
  // const zipOpen = Module.findExportByName('libDexHelper.so', 'zipOpen');
  // if (zipOpen) {
  //   log('[*] zipOpen : ', zipOpen);
  //   Interceptor.attach(zipOpen, {
  //     onEnter: function (_args) {
  //       log(`Hit zipOpen`);
  //       log(Stack.native(this.context));
  //     },
  //   });
  // }
}

// Experimental - this doesn't seem to ever get hit
export function forkerEtc() {
  const forkerPtr = dexBase.add(0x9e40c);
  Interceptor.attach(forkerPtr, {
    onEnter: function (_args) {
      log(`[*] fork was hit`);
    },
  });
}

export function _deobfuscateStrings() {
  const xorStuff = dexBase.add(0x18220);
  Interceptor.attach(xorStuff, {
    onEnter: function (args) {
      this.stringPtr = args[0];
    },
    onLeave: function (_retval) {
      log(
        `xorStuff - "${this.returnAddress.sub(
          dexBase ? dexBase.add(0x4) : 0x4,
        )}": "${this.stringPtr.readUtf8String()}",`,
      );
    },
  });

  // These seemingly never get hit if you are on art, likely dalvik specific things
  const unroller = dexBase.add(0x9e26c);
  Interceptor.attach(unroller, {
    onEnter: function (args) {
      this.stringPtr = args[0];
    },
    onLeave: function (_retval) {
      log(
        `unroller - "${this.returnAddress.sub(
          dexBase ? dexBase.add(0x4) : 0x4,
        )}": "${this.stringPtr.readUtf8String()}",`,
      );
    },
  });
}

/**
 * This seems to be fine, but also appears to "take a while"
 * for frida to finish, we may be missing things during this
 * period of time?
 */
function antiDebugThreadBlockerReplaceThreadFunctions() {
  const antiDebugThreadAddresses = [
    0x9ec5c,
    0xaa97c, // Main anti debug thread, looks for status of files and calls a sys_kill
    0x9d73c, // inotify checks

    // These don't appear to be required for the non-anti-debug functionality to work
    0xe3fd0,

    0x9d030,
    // 0xe3fcc,
  ];

  antiDebugThreadAddresses.forEach((address, index) => {
    Interceptor.replace(
      dexBase.add(address),
      new NativeCallback(
        function () {
          log(`===> skipping anti debug thread ${index}...`);
          return;
        },
        'void',
        ['void'],
      ),
    );
  });
}

// This is mitigated by the above things regardless
export function _antiDebugStrStr() {
  const discountStrStrPtr = dexBase.add(0x9de68);
  Interceptor.attach(discountStrStrPtr, {
    onEnter: function (args) {
      this.arg0 = args[0].readUtf8String();
      const buf = Memory.allocUtf8String('derp');
      this.buf = buf;
      args[1] = buf;
      this.arg1 = args[1].readUtf8String();
    },
    onLeave: function (retval) {
      log(`discountStrStr("${this.arg0}", "${this.arg1}") : ${retval}`);
      if (!retval.equals(0)) {
        log(` [!] replacing discountStrStr retval with 0`);
        retval.replace(ptr(0));
      }
    },
  });
}

function _antiDebugMapSeeker() {
  // Causes spurious segfaults that can look real, likely is checking to see if there
  // are hooks on the memory in/around libDexHelper.so
  // Crashes represent like the following:
  // 0x770f8afec0 libDexHelper.so!0x7cec0
  // 0x770f8b00c8 libDexHelper.so!_Z33p78C86B081F85A608BB75372604D6C75EPKc+0x2c
  // 0x770f8a5464 libDexHelper.so!_Z33p85949C9CA7704A6EFD2777EB9580B669i+0x808
  // 0x770f89fd8c libDexHelper.so!_Z33p9612F93FF34AFA81C8ABDBB91765B9A6v+0x380
  // 0x770f865eec libDexHelper.so!0x32eec
  // 0x770f86ee6c libDexHelper.so!JNI_OnLoad+0x3b3c
  // 0x779938a444 libart.so!_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_+0x600
  // 0x779938a444 libart.so!_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_+0x600

  // This is seemingly an anti-debug trap so we can just patch it out and skip it for the time being
  // _Z33p9612F93FF34AFA81C8ABDBB91765B9A6v
  // const _Z33p9612F93FF34AFA81C8ABDBB91765B9A6v = Module.findExportByName(
  //   'libDexHelper.so',
  //   '_Z33p9612F93FF34AFA81C8ABDBB91765B9A6v',
  // );
  // if (_Z33p9612F93FF34AFA81C8ABDBB91765B9A6v) {
  //   Interceptor.replace(
  //     _Z33p9612F93FF34AFA81C8ABDBB91765B9A6v,
  //     new NativeCallback(
  //       function () {
  //         log(' [+] skipping anti-debug techinique for scanning /proc/self/maps');
  //         return;
  //       },
  //       'void',
  //       ['void'],
  //     ),
  //   );
  // }

  // This is a similar solution, but less clean
  // _Z33pBB89D708E26FE3A73359BD23D6E2F4D8i
  const _Z33p85949C9CA7704A6EFD2777EB9580B669i = Module.findExportByName(
    targetLibrary,
    '_Z33p85949C9CA7704A6EFD2777EB9580B669i',
  );
  if (_Z33p85949C9CA7704A6EFD2777EB9580B669i) {
    Interceptor.replace(
      _Z33p85949C9CA7704A6EFD2777EB9580B669i,
      new NativeCallback(
        function (_int) {
          // log('skipping...');
          // unprotectLibArt()
          return 0;
        },
        'int',
        ['int'],
      ),
    );
  }

  // memoryHooks();
  // Another method, for inspecting furthur as well
  // p85949C9CA7704A6EFD2777EB9580B669
  // const failing = Module.findExportByName(
  //   'libDexHelper.so',
  //   '_Z33p85949C9CA7704A6EFD2777EB9580B669i',
  // );
  // if (failing) {
  //   log(`Hooking failing function p85949C9CA7704A6EFD2777EB9580B669 at ${failing}`);
  //   Interceptor.attach(failing, {
  //     onEnter: function (args) {
  //       log(`Hit p85949C9CA7704A6EFD2777EB9580B669 ${args[0]}`);
  //       log(Stack.native(this.context));

  //       // const strstrPtr = Module.findExportByName(null, 'strstr');
  //       // if (strstrPtr) {
  //       //   Interceptor.attach(strstrPtr, {
  //       //     onEnter: function (args) {
  //       //       if (!args[1].readUtf8String()?.includes('libart.so')) {
  //       //         this.check = true
  //       //         log(`strstr("${args[0].readUtf8String()}", "${args[1].readUtf8String()}")`)
  //       //       }
  //       //     },
  //       //     onLeave: function (retval) {
  //       //       if (this.check && retval && retval.compare(0) !== 0) {
  //       //         log(`strstr retval ${retval}`)
  //       //         retval.replace(ptr(0x0))
  //       //       }
  //       //     },
  //       //   });
  //       // }
  //     },
  //   });
  // }
}

/**
 * Similar to the above, targets the same threads being created,
 * however it replaces them during the pthread_create call, which
 * seems to "block" the execution better.
 *
 * Warning: Utilizing this seems to actually cause the issue where
 * we get a random segfault, unsure why, utilize the other method
 * where we just replace the methods all together
 */
export function _antiDebugThreadReplacer() {
  const pthreadCreate = Module.getExportByName('libc.so', 'pthread_create');
  log(`Hooking pthread_create : ${pthreadCreate}`);
  Interceptor.attach(pthreadCreate, {
    onEnter: function (args) {
      const functionAddress = args[2] as NativePointer;
      // Only step into extended functionality if the spawned thread originates from our
      // target library
      if (Stack.getModuleInfo(functionAddress).includes('DexHelper')) {
        // This will represent itself as segmentation faults if runs, it will also clear the pc / stack while accessing
        // unknown memory
        if (functionAddress.equals(dexBase.add(0x9ec5c))) {
          Interceptor.replace(
            dexBase.add(0x9ec5c),
            new NativeCallback(
              function () {
                log(`===> skipping anti debug thread 1...`);
                return;
              },
              'void',
              ['void'],
            ),
          );
        } else if (functionAddress.equals(dexBase.add(0xaa97c))) {
          Interceptor.replace(
            dexBase.add(0xaa97c),
            new NativeCallback(
              function () {
                log(`===> skipping anti debug thread 2...`);
                return;
              },
              'void',
              ['void'],
            ),
          );
        } else if (functionAddress.equals(dexBase.add(0x9d73c))) {
          // Performs inotify stuff
          Interceptor.replace(
            dexBase.add(0x9d73c),
            new NativeCallback(
              function () {
                log(`===> skipping anti debug thread 3...`);
                return;
              },
              'void',
              ['void'],
            ),
          );
        } else if (functionAddress.equals(dexBase.add(0xe3fd0))) {
          Interceptor.replace(
            dexBase.add(0xe3fd0),
            new NativeCallback(
              function () {
                log(`===> skipping anti debug thread 4...`);
                return;
              },
              'void',
              ['void'],
            ),
          );
        } else if (functionAddress.equals(dexBase.add(0x9d030))) {
          Interceptor.replace(
            dexBase.add(0x9d030),
            new NativeCallback(
              function () {
                log(`===> skipping anti debug thread 5...`);
                return;
              },
              'void',
              ['void'],
            ),
          );
        } else {
          log(` ======= >pthread_create : ${functionAddress} : ${functionAddress.sub(dexBase)}`);
          log(`===> pthread_create(${functionAddress}) for unknown thread`);
          log(Stack.native(this.context));
        }
      }
    },
  });
}

// Experimental why trying to avoid somethings, doesn't seem to help
function _unprotectLibArt() {
  const libArt = Process.findModuleByName('libart.so');

  if (libArt) {
    const ranges = libArt.enumerateRanges('---');
    ranges.forEach((rangeDetails) => {
      if (rangeDetails.protection !== 'rwx') {
        Memory.protect(rangeDetails.base, rangeDetails.size, 'rwx');
      }
      // log(`${rangeDetails.base} : ${rangeDetails.protection}`)
    });
  }
}

// https://cs.android.com/android/platform/superproject/+/master:art/libdexfile/dex/standard_dex_file.h;l=54?q=CodeItem&ss=android%2Fplatform%2Fsuperproject
// uint16_t registers_size_;            // the number of registers used by this code
// //   (locals + parameters)
// uint16_t ins_size_;                  // the number of words of incoming arguments to the method
// //   that this code is for
// uint16_t outs_size_;                 // the number of words of outgoing argument space required
// //   by this code for method invocation
// uint16_t tries_size_;                // the number of try_items for this instance. If non-zero,
// //   then these appear as the tries array just after the
// //   insns in this instance.
// uint32_t debug_info_off_;            // Holds file offset to debug info stream.

// uint32_t insns_size_in_code_units_;  // size of the insns array, in 2 byte code units
// uint16_t insns_[1];                  // actual array of bytecode.
function _readCodeItem(codeItem: NativePointer) {
  const registers_size = codeItem.readU16();
  const ins_size = codeItem.add(2).readU16();
  const outs_size = codeItem.add(4).readU16();
  const tries_size = codeItem.add(6).readU16();
  // There appears to be a few large instances that go across map boundries and causes an access
  // violation?
  const insns_size_in_code_units = codeItem.add(12).readU32();
  let insns: ArrayBuffer | null = null;
  if (insns_size_in_code_units < 85000) {
    insns = codeItem.add(16).readByteArray(insns_size_in_code_units * 2);
  }

  return {
    registers_size,
    ins_size,
    outs_size,
    tries_size,
    insns_size_in_code_units,
    insns: insns,
  };
}

function printCodeItem(codeItem: NativePointer) {
  log(`registers size ${codeItem.readU16()}`);
  log(`ins_size ${codeItem.add(2).readU16()}`);
  log(`outs_size ${codeItem.add(4).readU16()}`);
  log(`tries_size_ ${codeItem.add(6).readU16()}`);
  log(`debug_info_off_ ${codeItem.add(8).readU32()}`);
  const codeUnits = codeItem.add(12).readU32();
  log(`insns_size_in_code_units_ ${codeUnits}`);
  const instructions = codeItem.add(16).readByteArray(codeUnits * 2);
  if (instructions !== null) {
    const instructionsArray = new Uint8Array(instructions);

    log(`insns : ${Buffer.from(instructionsArray).toString('hex')}`);
  }

  log(
    hexdump(codeItem, {
      offset: 0,
      length: 2 + 2 + 2 + 2 + 4 + 4 + codeUnits * 2,
      header: true,
      ansi: true,
    }),
  );
}

function getCodeItemData(codeItem: NativePointer): ArrayBuffer | null {
  return codeItem.readByteArray(16 + codeItem.add(12).readU32() * 2);
}

function dumpCodeItem(needle: ArrayBuffer, codeItem: NativePointer) {
  const data = getCodeItemData(codeItem);
  if (data && needleMap.isOpen()) {
    needleMap.writeNeedle(new Uint8Array(needle), new Uint8Array(data));
  }
}

function isSame(a: ArrayBuffer, b: ArrayBuffer): boolean {
  const aUint = new Uint8Array(a);
  const bUint = new Uint8Array(b);

  if (aUint.length !== bUint.length) {
    return false;
  }

  for (let i = 0; i < aUint.length; i++) {
    if (aUint[i] !== bUint[i]) {
      return false;
    }
  }

  return true;
}

// https://cs.android.com/android/platform/superproject/+/master:art/runtime/instrumentation.cc;drc=61d06bbec93e335119066679a8b2ed138883ab0c;l=354
function hookedArt() {
  // this would be nice to get working, but unsure what is broken with it
  // const prettyMethodPtr = Module.getExportByName(
  //   'libart.so',
  //   '_ZN3art9ArtMethod12PrettyMethodEPS0_b',
  // );
  // if (prettyMethodPtr) {
  //   log(`got art::ArtMethod::PrettyMethod(art::ArtMethod*, bool) @ ${prettyMethodPtr}`);
  // }
  // const prettyMethod = new NativeFunction(prettyMethodPtr, 'pointer', ['pointer', 'bool']);
  // const prettyMethodPtr = Module.getExportByName('libart.so', '_ZN3art9ArtMethod12PrettyMethodEb');
  // const prettyMethod = new NativeFunction(prettyMethodPtr, 'pointer', [
  //   'pointer',
  //   'pointer',
  //   'bool',
  // ]);

  const getCodeItemPtr = Module.getExportByName('libart.so', 'NterpGetCodeItem');
  const getCodeItem = new NativeFunction(getCodeItemPtr, 'pointer', ['pointer']);

  // LOAD:0000000000048DA4 hooked_ZN3art15instrumentation15Instrumentation21InitializeMethodsCode_ZN3art15instrumentation15Instrumentation21InitializeMethodsCodeEPNS_9ArtMethodEPKv
  // LOAD:0000000000048DA4 ; DATA XREF: hook_art_initialize_methods_function+199C↓o
  // LOAD:0000000000048DA4 ; hook_art_initialize_methods_function+19A4↓o ...
  //
  // void Instrumentation::InitializeMethodsCode(ArtMethod* method, const void* aot_code)
  const initializeMethodsCode = dexBase.add(0x49958); // pilot // fly dexBase.add(0x48da4);
  Interceptor.attach(initializeMethodsCode, {
    onEnter: function (args) {
      // args[0] InitializeMethodsCode itself?
      // args[1] artmethod
      // args[2] aot_code
      this.curArtMethod = args[1];

      // Encrypted (or was never encrypted if it is there)
      const codeItem = getCodeItem(this.curArtMethod);
      if (codeItem.compare(0) !== 0) {
        this.incomingCodeItem = getCodeItemData(codeItem);
        // All the code item parts and the first four known bytes we just confirmed above along with the identifier
        // which should be unique
        this.needle = codeItem.readByteArray(16 + 8);
        if (debug) {
          log(` [+] initializeMethodsCode(${args[0]}, ${args[1]}, ${args[2]}) `);
          if (codeItem) {
            log(printCodeItem(codeItem));
          }
        }
      }
    },
    onLeave: function (_retval) {
      // Decrypted at this point
      if (this.incomingCodeItem) {
        const codeItem = getCodeItem(this.curArtMethod);
        const codeItemData = getCodeItemData(codeItem);
        if (codeItemData) {
          if (!isSame(this.incomingCodeItem, codeItemData) && !isSame(codeItemData, this.needle)) {
            dumpCodeItem(this.needle, codeItem);
            if (debug) {
              log(printCodeItem(codeItem));
              log(`<=======`);
            }
          }
        }
      }
    },
  });
}

function _linkerHooks() {
  const linkerHook = dexBase.add(0xa6ed4);
  Interceptor.attach(linkerHook, {
    onEnter: function (args) {
      log(`*************************************** INSIDE linkerHook ${args[0].readUtf8String()} `);
      // const library = args[0].readUtf8String();
      // if (library?.includes('libc++_shared.so')) {
      //   secneoJavaHooks()
      // }
      // if (library?.includes('libmsaoaidsec.so')) {
      //   library.replace('libmsaoaidsec', 'libdiffderpec')
      //   args[0] = Memory.allocUtf8String(library)
      // }
    },
    onLeave: function (_retval) {
      log(`*************************************** EXITING linkerHook`);
    },
  });
}

function _hookingEngine() {
  const get_libart_funaddrP = Module.findExportByName(
    targetLibrary,
    'p78C86B081F85A608BB75372604D6C75E',
  );
  if (get_libart_funaddrP) {
    Interceptor.attach(get_libart_funaddrP, {
      onEnter: function (_args) {
        log(`Hit get_libart_funaddrP`);
        log(Stack.native(this.context));
      },
    });
  }

  // 000000000007D1A0                 EXPORT _Z19get_libdexfile_funaddrPKc
  // Get function address from libdexfile
  const _Z19get_libdexfile_funaddrPKc = dexBase.add(0x7d1a0);
  Interceptor.attach(_Z19get_libdexfile_funaddrPKc, {
    onEnter: function (args) {
      this.funct = args[0].readUtf8String();
    },
    onLeave: function (retval) {
      log(`get_libdexfile_funaddr("${this.funct}") : ${retval}`);
    },
  });

  // LOAD:000000000007D09C                 EXPORT _Z19get_libart_funaddrPKc_p78C86B081F85A608BB75372604D6C75E
  const p78C86B081F85A608BB75372604D6C75E = dexBase.add(0x7d09c);
  Interceptor.attach(p78C86B081F85A608BB75372604D6C75E, {
    onEnter: function (args) {
      this.funct = args[0].readUtf8String();
    },
    onLeave: function (retval) {
      log(`get_libart_funaddr("${this.funct}") : ${retval}`);
    },
  });

  // LOAD:0000000000093EDC                 EXPORT hookedFunAddr_read
  const hookedFunctionPtr = dexBase.add(0x0000000000093edc);
  if (hookedFunctionPtr) {
    log('[*] hookFunctionPtr : ', hookedFunctionPtr);
    Interceptor.attach(hookedFunctionPtr, {
      onEnter: function (args) {
        // args[0] - function address to replace
        // args[1] - function address to replace with
        log(
          `hookFunction(${Stack.getModuleInfo(args[0])}, ${Stack.getModuleInfo(
            args[1],
          )}) : via ${Stack.getModuleInfo(this.returnAddress)}`,
        );
        const functionToReplace = Stack.getModuleInfo(args[0]);
        if (functionToReplace.includes('linker64')) {
          Interceptor.attach(args[1], {
            onEnter: function (args) {
              log(
                `*************************************** INSIDE linkerHook ${args[0].readUtf8String()} `,
              );
            },
            onLeave: function (_retval) {
              log(`*************************************** EXITING linkerHook`);
            },
          });
        }
        // const dexHelperReplacement = Stack.getModuleInfo(args[1])
        // if (!Stack.getModuleInfo(args[0]).includes('mmap')) {
        //   Interceptor.attach(args[1], {
        //     onEnter: function (args) {
        //       log(`Inside ${dexHelperReplacement} ******************************************** ${Stack.getModuleInfo(this.returnAddress)}`)
        //     }
        //   })
        // }
      },
      onLeave: function (_retval) {
        log(`left`);
      },
    });
  }

  // 0000000000089E00 hooked_read 93EDC
  const hooked_read = dexBase.add(0x0000000000089e00);
  if (hooked_read) {
    log('[*] hooked_read : ', hooked_read);
    Interceptor.attach(hooked_read, {
      onEnter: function (_args) {
        log(`Hit hooked_read`);
        log(Stack.native(this.context));
      },
    });
  }

  // const hookMethods = Module.findExportByName('libDexHelper.so', 'pCDF4A538018372C2F08E8231214F0E82');
  const hookMethods = dexBase.add(0x9528c);
  if (hookMethods) {
    log('[*] hookMethod : ', hookMethods);
    Interceptor.attach(hookMethods, {
      onEnter: function (args) {
        const dlHandle = args[0];
        const methodName = args[1].readUtf8String();
        const replacementPtr = args[2];
        log(
          ` [*] hookMethod(${dlHandle}, "${methodName}", ${Stack.getModuleInfo(
            replacementPtr,
          )}) : via ${Stack.getModuleInfo(this.returnAddress)}`,
        );
      },
    });
  }
}

export function hookDexHelper(anti = false, dumpDex = false, dumpMethods = false) {
  if (!dexBase) {
    dexBase = getDexBase();
  }

  if (anti) {
    antiDebugThreadBlockerReplaceThreadFunctions();
  }

  if (dumpDex) {
    dumpDexFiles();
  }

  if (dumpMethods) {
    hookedArt();
  }

  // _deobfuscateStrings()
  // antiDebugMapSeeker();
  // antiDebugStarter();
  // sysKillHook();
  // hookingEngine();

  // deobfuscateStrings();
  // systemlibcHooks();
  // antiDebugStrStr();

  // LOAD:0000000000099D60 ; __int64 __fastcall p9D9D5EBFFBA5037CD933AAD42AD3565D(int, int, int, char *)
  // const something = dexBase.add(0x99D60)
  // Interceptor.attach(something, {
  //   onEnter: function (args) {
  //     log(`*************************************** INSIDE IT`)
  //   }
  // })

  // Interceptor.replace(
  //   linkerHook,
  //   new NativeCallback(
  //     function () {
  //       log(`===> skipping linkerHook...`);
  //       return;
  //     },
  //     'void',
  //     ['void'],
  //   ),
  // );

  // LOAD:00000000000A62FC ; __int64 __fastcall p97E60F9036BDF243469376D1271EEF6C(char *haystack)
  // const antiCheck = dexBase.add(0xA62FC)
  // Interceptor.attach(antiCheck, {
  //   onEnter: function (args) {
  //     log(`**************** anticheck("${args[0].readUtf8String()}")`)
  //   },
  //   onLeave: function (retval) {
  //     log(`retval: ${retval}`)
  //   }
  // })

  // const otherCheck = dexBase.add(0x9E7F8)
  // Interceptor.attach(otherCheck, {
  //   onEnter: function (args) {
  //     log(`**************** otherCheck("${args[0]}")`)
  //   },
  //   onLeave: function (retval) {
  //     log(`retval: ${retval}`)
  //   }
  // })

  // 00000000000C07F0                 EXPORT p01054F2A1A944FB4581CF7C500BDC587
  // const checkStrcmp = dexBase.add(0xC07F0)
  // Interceptor.attach(checkStrcmp, {
  //   onEnter: function (args) {
  //     const strcmp = Module.findExportByName(null, 'strcmp');
  //     if (strcmp) {
  //       log('[*] hooked strcmp : ', strcmp);
  //       this.strcmpHook = Interceptor.attach(strcmp, {
  //         onEnter: function (args) {
  //           this.s1 = args[0].readUtf8String();
  //           this.s2 = args[1].readUtf8String();
  //         },
  //         onLeave: function (retval) {
  //           log(`strcmp(${this.s1}, ${this.s2})`);
  //         },
  //       });
  //     }
  //   }, onLeave: function (retval) {
  //     if (this.strcmpHook) {
  //       this.strcmpHook.detach()
  //     }

  //   }
  // })

  // const potentialAntiDebug = dexBase.add(0x1f3cc);
  // Interceptor.attach(potentialAntiDebug, {
  //   onEnter: function (args) {

  //       // const strncmp = Module.findExportByName(null, 'strncmp');
  //       // if (strncmp) {
  //       //   log('[*] hooked strcmp : ', strncmp);
  //       //   this.strncmp = Interceptor.attach(strncmp, {
  //       //     onEnter: function (args) {
  //       //       this.s1 = args[0].readUtf8String();
  //       //       this.s2 = args[1].readUtf8String();
  //       //     },
  //       //     onLeave: function (_retval) {
  //       //        log(`strncmp(${this.s1}, ${this.s2})`);
  //       //     },
  //       //   });
  //       // }

  //     log(`what is this ${args[0]}`);
  //     log(
  //       hexdump(args[0], {
  //         offset: 0,
  //         length: 10,
  //         header: true,
  //         ansi: true,
  //       }),
  //     );
  //     log(Stack.native(this.context));
  //   },
  //   onLeave: function (retval) {
  //     log(`retval : ${retval}`);
  //     retval.replace(ptr(0x0))
  //     if (this.strncmp) {
  //       this.strncmp.detach()
  //     }
  //   },
  // });

  // const failedHook = dexBase.add(0x723f8)
  // Interceptor.attach(failedHook, {
  //   onEnter: function (args) {
  //     log(`prefailure ? `)
  //     log(Stack.native(this.context))
  //   }
  // })

  // Some type of deobfuscator?
  // p599D1379FBA84EB0A62F0E0FBA8C17D0
  // const test = dexBase.add(0x38FB8)
  //   Interceptor.attach(test, {
  //   onEnter: function (args) {
  //     log(`test ? `)
  //     // log(hexdump(args[0], {
  //     //     offset: 0,
  //     //     length: 10,
  //     //     header: true,
  //     //     ansi: true,
  //     //   }))
  //     log(Stack.native(this.context))
  //     log(JSON.stringify(this.context))
  //     log(hexdump((this.context as Arm64CpuContext).x19, {
  //       offset: 0,
  //       length: 16,
  //       header: true,
  //       ansi: true,
  //     }))
  //   },
  //   onLeave: function (retval) {
  //     log(`retval : ${retval}`)
  //   }
  // })

  // const pA0B37C1ACAF5E4A3E567EF01AC00E282 = Module.findExportByName(
  //   'libDexHelper.so',
  //   'pA0B37C1ACAF5E4A3E567EF01AC00E282',
  // );
  // if (pA0B37C1ACAF5E4A3E567EF01AC00E282) {
  //   log('[*] pA0B37C1ACAF5E4A3E567EF01AC00E282 : ', pA0B37C1ACAF5E4A3E567EF01AC00E282);
  //   Interceptor.attach(pA0B37C1ACAF5E4A3E567EF01AC00E282, {
  //     onEnter: function (args) {
  //       log(`Hit pA0B37C1ACAF5E4A3E567EF01AC00E282 : ${args[0]} : ${args[1].readUtf8String()}}`);
  //       hexdump(args[0], {
  //         offset: 0,
  //         length: 10,
  //         header: true,
  //         ansi: true,
  //       });
  //       log(Stack.native(this.context));
  //     },
  //     onLeave: function (retval) {
  //       log(`pA0B37C1ACAF5E4A3E567EF01AC00E282 retval ${retval}`);
  //     },
  //   });
  // }

  // const sometype_of_antidebug_hooks = Module.findExportByName(
  //   targetLibrary,
  //   'p1B20B84FF8C44DD69552223AF70D932F',
  // );
  // if (sometype_of_antidebug_hooks) {
  //   Interceptor.attach(sometype_of_antidebug_hooks, {
  //     onEnter: function (args) {

  //     },
  //     onLeave: function (retval) {
  //       log(`sometype_of_antidebug_hooks : ${retval}`)
  //     }
  //   })
  // Interceptor.replace(
  //   sometype_of_antidebug_hooks,
  //   new NativeCallback(
  //     function () {
  //       log(`===> skipping some replacement function thing...`);
  //       return new NativeCallback(
  //         function () {
  //           log(`someone called me?!`);
  //         },
  //         'void',
  //         ['void'],
  //       );
  //     },
  //     'pointer',
  //     ['pointer', 'pointer'],
  //   ),
  // );
  // }

  // LOAD:0000000000067810 ; __int64 __fastcall setup_zipres(char *, char *, char *, int)
  // const setupZipRes = Module.findBaseAddress('libDexHelper.so')?.add(0x67810);
  // if (setupZipRes) {
  //   log('[*] setupZipRes : ', setupZipRes);
  //   Interceptor.attach(setupZipRes, {
  //     onEnter: function (args) {
  //       log(
  //         `Hit setupZipRes - ${args[0].readUtf8String()} : ${args[1].readUtf8String()} : ${args[2].readUtf8String()}`,
  //       );
  //       log(Stack.native(this.context));
  //     },
  //   });
  // }

  // 00000000000894D0                 EXPORT decrypt_jar_128K
  // const decrypt_jar_128K = Module.findBaseAddress('libDexHelper.so')?.add(0x894d0);
  // if (decrypt_jar_128K) {
  //   log('[*] decrypt_jar_128K : ', decrypt_jar_128K);
  //   Interceptor.attach(decrypt_jar_128K, {
  //     onEnter: function (_args) {
  //       // this.arg0 = args[0];
  //       log(`Hit decrypt_jar_128K`);
  //       // log(Stack.native(this.context));
  //       // hexdump(args[0], {
  //       //   offset: 0,
  //       //   length: 10,
  //       //   header: true,
  //       //   ansi: true,
  //       // });
  //     },
  //     onLeave: function (_retval) {
  //       // hexdump(this.arg0, {
  //       //   offset: 0,
  //       //   length: 10,
  //       //   header: true,
  //       //   ansi: true,
  //       // });
  //     },
  //   });
  // }

  // LOAD:0000000000091CBC ; __int64 __fastcall loadInMemoryDgc(unsigned __int8 *, int, unsigned int)
  // LOAD:0000000000091CBC                 EXPORT _Z15loadInMemoryDgcPhij
  // const _Z15loadInMemoryDgcPhij = Module.findBaseAddress('libDexHelper.so')?.add(0x091cbc);
  // if (_Z15loadInMemoryDgcPhij) {
  //   log('[*] _Z15loadInMemoryDgcPhij : ', _Z15loadInMemoryDgcPhij);
  //   Interceptor.attach(_Z15loadInMemoryDgcPhij, {
  //     onEnter: function (_args) {
  //       log(`Hit _Z15loadInMemoryDgcPhij`);
  //       log(Stack.native(this.context));
  //     },
  //   });
  // }

  // strcmp inside hookMethods

  // const strCmpHookMethods = dexBase.add(0x95340)
  // Interceptor.attach(strCmpHookMethods, {
  //   onEnter: function (args) {
  //     const s1 = (this.context as Arm64CpuContext).x0.readUtf8String();
  //     const s2 = (this.context as Arm64CpuContext).x1.readUtf8String();
  //     log(`strcmp("${s1}", "${s2})"`);
  //   },
  // })

  // const findCorrectSharedLibPath = dexBase?.add(0x7cec0);
  // Interceptor.attach(findCorrectSharedLibPath, {
  //   onEnter: function (args) {
  //     log(`findCorrectSharedLibPath("${args[0].readUtf8String()}")`);
  //   },hreadAddresses.forEach((address, index) => {
  //   Interceptor.replace(
  //     dexBase.add(address),
  //     new NativeCallback(
  //       function () {
  //         log(`===> skipping anti debug thread ${index}...`);
  //         return;
  //       },
  //       'void',
  //       ['void'],
  //     ),
  //   );
  // });
  //   onLeave: function (retval) {
  //     log(
  //       `RETURNING`
  //       // `returning ${retval.readUtf8String()} from ${this.returnAddress.sub(dexBase).sub(0x1)}`,
  //     );
  //   },
  // });

  // Interceptor.replace(
  //   dexBase?.add(0x7cec0),
  //   new NativeCallback(
  //     function (int) {
  //       log('skipping...');
  //       return 0;
  //     },
  //     'int', ['int'],
  //   ),
  // );

  // For tracking the switched in the broken functions, this is still unclear
  // const switchPtr = dexBase.add(0x71e44);
  // Interceptor.attach(switchPtr, {
  //   onEnter: function (args) {
  //     log(
  //       ` >>>>>>>>>>>>>>>>>>>>> IT GOT CALLED ${args[0].sub(
  //         dexBase,
  //       )} : ${args[0].toInt32()} : ${dexBase.add(0x72318).toInt32()}`,
  //     );
  //   },
  // });

  // For modifiying the flattened control flow to just try and avoid the crash for a bit longer
  // const switchPtr2 = dexBase.add(0x722f4);
  // Interceptor.attach(switchPtr2, {
  //   onEnter: function (args) {
  //     log(` >>>>>>>>>>>>>>>>>>>>> IT GOT CALLED 2 ${args[0].sub(dexBase)}`);
  //     if (args[0].equals(dexBase.add(0x72318))) {
  //       args[0] = dexBase.add(0x71e90);
  //       log(` >>>>>>>>>>>>>>>>>>>>> IT GOT CHANGED ${args[0].sub(dexBase)}`);
  //     }
  //   },
  // });
}

function getNeededClasses(): string[] {
  return [
    'am/util/viewpager/adapter/FragmentRemovePagerAdapter',
    'derp/derpy/derpiness'
  ];
}
