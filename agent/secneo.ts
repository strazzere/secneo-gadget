import { log } from './logger';
import { Stack } from './stack';
import { writeDexToFile } from './dex';
import { systemlibcHooks } from './systemlibc';
import { memoryHooks } from './mem';

const targetLibrary = 'libDexHelper.so';

const stack = new Stack();

const getStack = () => {
  log(stack.java());
};

let dexBase: NativePointer;

function getDexBase(): NativePointer {
  const base = Module.findBaseAddress(targetLibrary);
  if (!base) {
    throw new Error(`Unable to get base address for ${targetLibrary}`);
  }

  return base;
}

export function secneoJavaHooks() {
  // Java.perform(function () {
  //   const aw = Java.use(`com.secneo.apkwrapper.AW`);
  //   log(`Hooking AW`);
  //   aw.attachBaseContext.overload('android.content.Context').implementation = function (
  //     context: Java.Wrapper<object>,
  //   ) {
  //     log(` > attachBaseContext called`);
  //     getStack();
  //     this.attachBaseContext(context);
  //   };
  // });
}

export function dumpDexFiles() {
  // LOAD:0000000000031684 ; __int64 __fastcall expandedv2data(char *p, int, int *)
  // LOAD:0000000000031684                 EXPORT _Z14expandedv2dataPciPi
  const _Z14expandedv2dataPciPi = dexBase.add(0x031684);
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
    onEnter: function (args) {
      log(`[*] fork was hit`);
    },
  });
}

// Experimental, this is the hook for an svc call to __NR_kill (sys kill)
function sysKillHook() {
  const sysKillPtr = Module.findExportByName(targetLibrary, 'p8A01F8A04CC4D64E56A88E4D1466B151');
  // const sysKillPtr = dexBase.add(0xA8E00)
  if (sysKillPtr) {
    log(` [+] hooked syskill function p8A01F8A04CC4D64E56A88E4D1466B151`);
    Interceptor.attach(sysKillPtr, {
      onEnter: function (_args) {
        log(` [!] Hit a syskill function! Did not change the value or replace it at all`);
      },
    });
  }
}

// This is the routine that would have called the above sys kill call
function antiDebugStarter() {
  const sysKillPtr = Module.findExportByName(targetLibrary, 'pDC54CD4743EC5AAF6F30EA9C1C92801D');
  // const sysKillPtr = dexBase.add(0xA8E00)
  if (sysKillPtr) {
    log(` replacing syskill antidebug thread`);
    Interceptor.replace(
      sysKillPtr,
      new NativeCallback(
        function () {
          log(`===> skipping anti debug routine...`);
          return;
        },
        'void',
        ['void'],
      ),
    );
  }
}

export function deobfuscateStrings() {
  // const xorStuff = dexBase.add(0x18220);
  // Interceptor.attach(xorStuff, {
  //   onEnter: function (args) {
  //     this.stringPtr = args[0];
  //   },
  //   onLeave: function (_retval) {
  //     log(
  //       `xorStuff - "${this.returnAddress.sub(
  //         dexBase ? dexBase.add(0x4) : 0x4,
  //       )}": "${this.stringPtr.readUtf8String()}",`,
  //     );
  //   },
  // });

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
function _antiDebugThreadBlockerReplaceThreadFunctions() {
  const antiDebugThreadAddresses = [
    0x9ec5c,
    0xaa97c, // Main anti debug thread, looks for status of files and calls a sys_kill
    0x9d73c,
    0xe3fd0, // might not be needed to be blocked?

    0x9d030,
    0xe3fcc,
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

export function antiDebugStrStr() {
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

function antiDebugMapSeeker() {
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
        function (int) {
          log('skipping...');
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
 */
export function antiDebugThreadReplacer() {
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

function hookingEngine() {
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
      log(`_Z19get_libdexfile_funaddrPKc(${this.funct}) : ${retval}`);
    },
  });

  // LOAD:000000000007D09C                 EXPORT _Z19get_libart_funaddrPKc_p78C86B081F85A608BB75372604D6C75E
  const p78C86B081F85A608BB75372604D6C75E = dexBase.add(0x7d09c);
  Interceptor.attach(p78C86B081F85A608BB75372604D6C75E, {
    onEnter: function (args) {
      this.funct = args[0].readUtf8String();
    },
    onLeave: function (retval) {
      log(`_Z19get_libart_funaddrPKc_p78C86B081F85A608BB75372604D6C75E(${this.funct}) : ${retval}`);
    },
  });

  // LOAD:0000000000093EDC                 EXPORT hookedFunAddr_read
  const hookedFunctionPtr = dexBase.add(0x0000000000093edc);
  if (hookedFunctionPtr) {
    log('[*] hookedFunctionPtr : ', hookedFunctionPtr);
    Interceptor.attach(hookedFunctionPtr, {
      onEnter: function (args) {
        // args[0] - dlsym address for shared library

        log(
          `Hit hookedFunction (${Stack.getModuleInfo(args[0])}, ${Stack.getModuleInfo(args[1])})`,
        );

        log(Stack.native(this.context));
      },
      onLeave: function (retval) {
        log(`Hit hookedFunction retval ${retval}`);
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
        log(` [*] hookMethod(${dlHandle}, ${methodName}, ${Stack.getModuleInfo(replacementPtr)})`);
        log(Stack.native(this.context));
      },
    });
  }
}

export function hookDexHelper() {
  if (!dexBase) {
    dexBase = getDexBase();
  }
  antiDebugMapSeeker();
  antiDebugStarter();
  sysKillHook();
  hookingEngine();
  // deobfuscateStrings();
  // systemlibcHooks();
  // antiDebugStrStr();

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

  const sometype_of_antidebug_hooks = Module.findExportByName(
    targetLibrary,
    'p1B20B84FF8C44DD69552223AF70D932F',
  );
  if (sometype_of_antidebug_hooks) {
    Interceptor.replace(
      sometype_of_antidebug_hooks,
      new NativeCallback(
        function () {
          log(`===> skipping some replacement function thing...`);
          return new NativeCallback(
            function () {
              log(`someone called me?!`);
            },
            'void',
            ['void'],
          );
        },
        'pointer',
        ['pointer', 'pointer'],
      ),
    );
  }

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
