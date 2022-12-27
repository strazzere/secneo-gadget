import { log } from './logger';
import { Stack } from './stack';
import { hookCallFunction } from './linker';

const stack = new Stack();
const getStack = () => {
  log(stack.java());
};

let hooked = false;

function hookDexHelper() {
  const openPtr = Module.findExportByName(null, 'open');
  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) {
        const fileName = args[0].readUtf8String();
        log(`[*] open - ${fileName}`);
      },
      onLeave: function (retval) {
        log(`[*] open retval - ${retval}`);
        log(Stack.native(this.context));
      },
    });
  }

  const fopenPtr = Module.findExportByName(null, 'fopen');
  if (fopenPtr) {
    Interceptor.attach(fopenPtr, {
      onEnter: function (args) {
        const fileName = args[0].readUtf8String();
        const mode = args[1].readUtf8String();
        log(`[*] fopen - ${fileName} with mode ${mode}`);
      },
      onLeave: function (_retval) {
        log(Stack.native(this.context));
      },
    });
  }

  const accessPtr = Module.findExportByName(null, 'access');
  if (accessPtr) {
    log('[*] hooked access : ', accessPtr);
    Interceptor.attach(accessPtr, {
      onEnter: function (args) {
        this.file = args[0].readUtf8String();
      },
      onLeave: function (retval) {
        log('[+] access :', this.file, 'ret :', retval);
        log(Stack.native(this.context));
      },
    });
  }

  // LOAD:000000000003B484 loc_3B484                               ; CODE XREF: sub_385BC+2EA0↑j
  // LOAD:000000000003B484                 LDR             X0, [X29,#0x108]
  // LOAD:000000000003B488                 MOV             X2, #0x10 ; size_t
  // LOAD:000000000003B48C                 MOV             W19, #0
  // LOAD:000000000003B490                 LDR             X1, [X0,#0x9C0] ; void *
  // LOAD:000000000003B494                 MOV             X0, X25 ; void *
  // LOAD:000000000003B498                 BL              .memcmp
  // hook the above specific call to .memcmp and inspect the contents
  // this is likely the md5 (?) check against the original classes.dex for integrity check, I think?
  const memcmp = Module.findBaseAddress('libDexHelper.so')?.add(0x0003b498);
  if (memcmp) {
    log('[*] hooked specific memcmp : ', memcmp);
    Interceptor.attach(memcmp, {
      onEnter: function (args) {
        log('specific memcmp');
        console.log(
          hexdump(args[0], {
            offset: 0,
            length: args[2].toInt32(),
            header: true,
            ansi: true,
          }),
        );
        console.log(
          hexdump(args[1], {
            offset: 0,
            length: args[2].toInt32(),
            header: true,
            ansi: true,
          }),
        );
        log(Stack.native(this.context));
      },
      onLeave: function (retval) {
        log(`memcmp equal ret: ${retval}`);
      },
    });
  }

  // 00000000000CE44C                 EXPORT zipOpen
  const zipOpen = Module.findExportByName('libDexHelper.so', 'zipOpen');
  if (zipOpen) {
    log('[*] zipOpen : ', zipOpen);
    Interceptor.attach(zipOpen, {
      onEnter: function (_args) {
        log(`Hit zipOpen`);
        log(Stack.native(this.context));
      },
    });
  }

  const pA0B37C1ACAF5E4A3E567EF01AC00E282 = Module.findExportByName(
    'libDexHelper.so',
    'pA0B37C1ACAF5E4A3E567EF01AC00E282',
  );
  if (pA0B37C1ACAF5E4A3E567EF01AC00E282) {
    log('[*] pA0B37C1ACAF5E4A3E567EF01AC00E282 : ', pA0B37C1ACAF5E4A3E567EF01AC00E282);
    Interceptor.attach(pA0B37C1ACAF5E4A3E567EF01AC00E282, {
      onEnter: function (args) {
        log(
          `Hit pA0B37C1ACAF5E4A3E567EF01AC00E282 : ${args[0].toInt32()} : ${args[1].readUtf8String()}}`,
        );
        log(Stack.native(this.context));
      },
    });
  }

  // 0000000000089E00 hooked_read
  const hooked_read = Module.findBaseAddress('libDexHelper.so')?.add(0x0000000000089e00);
  if (hooked_read) {
    log('[*] hooked_read : ', hooked_read);
    Interceptor.attach(hooked_read, {
      onEnter: function (_args) {
        log(`Hit hooked_read`);
        log(Stack.native(this.context));
      },
    });
  }

  // LOAD:0000000000067810 ; __int64 __fastcall setup_zipres(char *, char *, char *, int)
  const setupZipRes = Module.findBaseAddress('libDexHelper.so')?.add(0x67810);
  if (setupZipRes) {
    log('[*] setupZipRes : ', setupZipRes);
    Interceptor.attach(setupZipRes, {
      onEnter: function (args) {
        log(
          `Hit setupZipRes - ${args[0].readUtf8String()} : ${args[1].readUtf8String()} : ${args[2].readUtf8String()}`,
        );
        log(Stack.native(this.context));
      },
    });
  }

  // LOAD:0000000000031684 ; __int64 __fastcall expandedv2data(char *p, int, int *)
  // LOAD:0000000000031684                 EXPORT _Z14expandedv2dataPciPi
  const _Z14expandedv2dataPciPi = Module.findBaseAddress('libDexHelper.so')?.add(0x031684);
  if (_Z14expandedv2dataPciPi) {
    log('[*] _Z14expandedv2dataPciPi : ', _Z14expandedv2dataPciPi);
    Interceptor.attach(_Z14expandedv2dataPciPi, {
      onEnter: function (args) {
        log(
          `Hit _Z14expandedv2dataPciPi : "${args[0].readUtf8String()}" : ${
            args[1]
          } : ${args[2].readU32()}`,
        );
        log(Stack.native(this.context));
      },
    });
  }

  // 00000000000894D0                 EXPORT decrypt_jar_128K
  const decrypt_jar_128K = Module.findBaseAddress('libDexHelper.so')?.add(0x894d0);
  if (decrypt_jar_128K) {
    log('[*] decrypt_jar_128K : ', decrypt_jar_128K);
    Interceptor.attach(decrypt_jar_128K, {
      onEnter: function (args) {
        this.arg0 = args[0];
        log(`Hit decrypt_jar_128K`);
        log(Stack.native(this.context));
        hexdump(args[0], {
          offset: 0,
          length: 10,
          header: true,
          ansi: true,
        });
      },
      onLeave: function (_retval) {
        hexdump(this.arg0, {
          offset: 0,
          length: 10,
          header: true,
          ansi: true,
        });
      },
    });
  }

  // LOAD:0000000000091CBC ; __int64 __fastcall loadInMemoryDgc(unsigned __int8 *, int, unsigned int)
  // LOAD:0000000000091CBC                 EXPORT _Z15loadInMemoryDgcPhij
  const _Z15loadInMemoryDgcPhij = Module.findBaseAddress('libDexHelper.so')?.add(0x091cbc);
  if (_Z15loadInMemoryDgcPhij) {
    log('[*] _Z15loadInMemoryDgcPhij : ', _Z15loadInMemoryDgcPhij);
    Interceptor.attach(_Z15loadInMemoryDgcPhij, {
      onEnter: function (_args) {
        log(`Hit _Z15loadInMemoryDgcPhij`);
        log(Stack.native(this.context));
      },
    });
  }

  // const hookMethods = Module.findExportByName('libDexHelper.so', 'pCDF4A538018372C2F08E8231214F0E82');
  const hookMethods = Module.findBaseAddress('libDexHelper.so')?.add(0x9528c);
  if (hookMethods) {
    log('[*] hookMethods : ', hookMethods);
    Interceptor.attach(hookMethods, {
      onEnter: function (args) {
        log('Hit hookMethod!');
        const dlHandle = args[0];
        const methodName = args[1].readUtf8String();
        const replacementPtr = args[2];
        log(
          '[*] handle : ' +
            dlHandle +
            ' methodName : ' +
            methodName +
            ' replacementPtr : ' +
            replacementPtr,
        );
        log(Stack.native(this.context));
      },
    });
  }
}

log(`Calling hookCallFunction`);
const hookedStuff = hookCallFunction('libDexHelper', (context, functionName, pointer) => {
  log(`Hit function call back for hookCallFunction for ${functionName} and value is ${pointer}`);
  // There is likely to never be anything but a native stack available at this point
  log(Stack.native(context))
});

const dlopenPtr = Module.findExportByName(null, 'dlopen');
if (dlopenPtr) {
  log('[*] hooked dlopen : ', dlopenPtr);
  Interceptor.attach(dlopenPtr, {
    onEnter: function (args) {
      if (!hooked && Stack.native(this.context).includes('libDexHelper')) {
        hookDexHelper();
        hooked = true;
      }
      this.libName = args[0].readUtf8String();
    },
    onLeave: function (retval) {
      log('[*] dlopen :', this.libName, 'ret :', retval);
    },
  });
}

const pthreadCreate = Module.getExportByName('libc.so', 'pthread_create');
Interceptor.attach(pthreadCreate, {
  onEnter(args) {
    const functionAddress = args[2] as NativePointer;
    log(`pthread_create : ${functionAddress.toString(16)}`);
    log(Stack.native(this.context));
  },
});

const dlsymPtr = Module.findExportByName(null, 'dlsym');
if (dlsymPtr) {
  Interceptor.attach(dlsymPtr, {
    onEnter: function (args) {
      this.handle = args[0];
      this.funcName = args[1].readUtf8String();
    },
    onLeave: function (retval) {
      log('[*] dlsym - handle :', this.handle, 'funcName :', this.funcName, 'ret :', retval);
    },
  });
}

const unlinkPtr = Module.findExportByName(null, 'unlink');
if (unlinkPtr) {
  Interceptor.attach(unlinkPtr, {
    onEnter: function (args) {
      log(`Unlink - ${args[0].readUtf8String()}`);
      log(Stack.native(this.context));
    },
  });
}

log(`(Re?)loaded : ${hookedStuff}`);
