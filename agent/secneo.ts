import { log } from './logger';
import { Stack } from './stack';
import { writeDexToFile } from './dex';
import { systemlibcHooks } from './systemlibc';

const stack = new Stack();

const getStack = () => {
  log(stack.java());
};

let dexBase: NativePointer;

function getDexBase(): NativePointer {
  const base = Module.findBaseAddress('libDexHelper.so');
  if (!base) {
    throw new Error(`Unable to get base address for libDexHelper.so`);
  }

  return base;
}

export function secneoJavaHooks() {
  Java.perform(function () {
    const aw = Java.use(`com.secneo.apkwrapper.AW`);
    log(`Hooking AW`);
    aw.attachBaseContext.overload('android.content.Context').implementation = function (
      context: Java.Wrapper<object>,
    ) {
      log(` > attachBaseContext called`);
      getStack();
      this.attachBaseContext(context);
    };
  });
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
}

// Experimental - this doesn't seem to ever get hit
export function forkerEtc() {
  const forkerPtr = dexBase.add(0x9E40C)
  Interceptor.attach(forkerPtr, {
    onEnter: function (args) {
      log(`[*] fork was hit`)
    },
  });
}

// Experimental, this is the hook for an svc call to __NR_kill (sys kill)
function sysKillHook() {
  const sysKillPtr = Module.findExportByName('libDexHelper.so', 'p8A01F8A04CC4D64E56A88E4D1466B151')
  // const sysKillPtr = dexBase.add(0xA8E00)
  if (sysKillPtr) {
    log(` hooked syskill p8A01F8A04CC4D64E56A88E4D1466B151`)
    Interceptor.attach(sysKillPtr, {
      onEnter: function (args) {
        log(`************** hit a sys kill ptr!`)
      },
    });
  }
}

// Experimental - this is the thread that would have called the above sys kill call
function antiDebugStarter() {
  const sysKillPtr = Module.findExportByName('libDexHelper.so', 'pDC54CD4743EC5AAF6F30EA9C1C92801D')
  // const sysKillPtr = dexBase.add(0xA8E00)
  if (sysKillPtr) {
    log(` hooked syskill pDC54CD4743EC5AAF6F30EA9C1C92801D`)
    Interceptor.attach(sysKillPtr, {
      onEnter: function (args) {
        log(`************** hit a sys pDC54CD4743EC5AAF6F30EA9C1C92801DpDC54CD4743EC5AAF6F30EA9C1C92801DpDC54CD4743EC5AAF6F30EA9C1C92801D!`)
      },
    });
  }
}

export function deobfuscateStrings() {
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

  const unroller = dexBase.add(0x9E26C)
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
      this.arg0 = args[0].readUtf8String()
      const buf = Memory.allocUtf8String('derp');
      this.buf = buf;
      args[1] = buf;
      this.arg1 = args[1].readUtf8String()
    },
    onLeave: function (retval) {
      log(`discountStrStr("${this.arg0}", "${this.arg1}") : ${retval}`);
      if (!retval.equals(0)) {
         log(` [!] replacing discountStrStr retval with 0`);
        retval.replace(ptr(0))
      }
    },
  });
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
      if (DebugSymbol.fromAddress(functionAddress).moduleName?.includes('DexHelper')) {
        log(` ======= >pthread_create : ${functionAddress} : ${functionAddress.sub(dexBase)}`);
        // This will represent itself as segmentation faults if runs, it will also clear the pc / stack while accessing
        // unknown memory
        if (functionAddress.equals(dexBase.add(0x9ec5c))) {
          systemlibcHooks();
          antiDebugStrStr()
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
          log(`===> pthread_create(${functionAddress}) for unknown thread`);
          log(Stack.native(this.context));
        }
      }
    },
  });
}

export function hookDexHelper() {
  if (!dexBase) {
    dexBase = getDexBase();
  }
  antiDebugStarter()
  sysKillHook()
  deobfuscateStrings()
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
  //         log('skipping...');
  //         return;
  //       },
  //       'void',
  //       ['void'],
  //     ),
  //   );
  // }

  // _Z33pBB89D708E26FE3A73359BD23D6E2F4D8i
  // const _Z33p85949C9CA7704A6EFD2777EB9580B669i = Module.findExportByName(
  //   'libDexHelper.so',
  //   '_Z33p85949C9CA7704A6EFD2777EB9580B669i',
  // );
  // if (_Z33p85949C9CA7704A6EFD2777EB9580B669i) {
  //   Interceptor.replace(
  //     _Z33p85949C9CA7704A6EFD2777EB9580B669i,
  //     new NativeCallback(
  //       function (int) {
  //         log('skipping...');
  //         return 0;
  //       },
  //       'int',
  //       ['int'],
  //     ),
  //   );
  // }

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
  //       //         log(`strstr("${args[0].readUtf8String()}", "${args[1].readUtf8String()}")`)
  //       //       }
  //       //     },
  //       //     onLeave: function (retval) {
  //       //       // if (retval) {
  //       //       //   log(`strstr retval ${retval}`)
  //       //       // }
  //       //     },
  //       //   });
  //       // }
  //     },
  //   });
  // }

  // const get_libart_funaddrP = Module.findExportByName(
  //   'libDexHelper.so',
  //   'p78C86B081F85A608BB75372604D6C75E',
  // );
  // if (get_libart_funaddrP) {
  //   Interceptor.attach(get_libart_funaddrP, {
  //     onEnter: function (_args) {
  //       log(`Hit get_libart_funaddrP`);
  //       log(Stack.native(this.context));
  //     },
  //   });
  // }

  // LOAD:0000000000093EDC                 EXPORT hookedFunAddr_read
  // const hookedFunAddr_read = Module.findBaseAddress('libDexHelper.so')?.add(0x0000000000093edc);
  // if (hookedFunAddr_read) {
  //   log('[*] hookedFunAddr_read : ', hookedFunAddr_read);
  //   Interceptor.attach(hookedFunAddr_read, {
  //     onEnter: function (_args) {
  //       log(`Hit hookedFunAddr_read`);
  //       log(Stack.native(this.context));
  //     },
  //   });
  // }

  // 0000000000089E00 hooked_read 93EDC
  // const hooked_read = Module.findBaseAddress('libDexHelper.so')?.add(0x0000000000089e00);
  // if (hooked_read) {
  //   log('[*] hooked_read : ', hooked_read);
  //   Interceptor.attach(hooked_read, {
  //     onEnter: function (_args) {
  //       log(`Hit hooked_read`);
  //       log(Stack.native(this.context));
  //     },
  //   });
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

  // const hookMethods = Module.findExportByName('libDexHelper.so', 'pCDF4A538018372C2F08E8231214F0E82');
  // const hookMethods = Module.findBaseAddress('libDexHelper.so')?.add(0x9528c);
  // if (hookMethods) {
  //   log('[*] hookMethods : ', hookMethods);
  //   Interceptor.attach(hookMethods, {
  //     onEnter: function (args) {
  //       log('Hit hookMethod!');
  //       const dlHandle = args[0];
  //       const methodName = args[1].readUtf8String();
  //       const replacementPtr = args[2];
  //       log(
  //         '[*] handle : ' +
  //           dlHandle +
  //           ' methodName : ' +
  //           methodName +
  //           ' replacementPtr : ' +
  //           replacementPtr,
  //       );
  //       log(Stack.native(this.context));
  //     },
  //   });
  // }

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

  deobfuscateStrings()
}
