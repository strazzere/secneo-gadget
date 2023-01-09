import { log } from './logger';
import { Stack } from './stack';

const debug = true;

export function systemlibcHooks() {
  if (debug) {
    log(` [*] hooking generic system/libc methods`);
  }

  openHook();
  // fopenHook();
  strcmpHook();

  if (debug) {
    log(` [+] finished hooking generic system/libc methods`);
  }
}

function openHook() {
  const openPtr = Module.findExportByName(null, 'open');
  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) {
        const fileName = args[0].readUtf8String();
        log(`[*] open - ${fileName}`);
        // log(Stack.native(this.context));
      },
    });
  }
}

function fopenHook() {
  const fopenPtr = Module.findExportByName(null, 'fopen');
  if (fopenPtr) {
    Interceptor.attach(fopenPtr, {
      onEnter: function (args) {
        const fileName = args[0].readUtf8String();
        const mode = args[1].readUtf8String();
        log(`[*] fopen - ${fileName} with mode ${mode}`);
        // log(Stack.native(this.context));
      },
    });
  }
}

function strcmpHook() {
  const strcmp = Module.findExportByName(null, 'strcmp');
  if (strcmp) {
    log('[*] hooked strcmp : ', strcmp);
    Interceptor.attach(strcmp, {
      onEnter: function (args) {
        this.s1 = args[0].readUtf8String();
        this.s2 = args[1].readUtf8String();
      },
      onLeave: function (retval) {
        if (retval.toInt32() === 0 && Stack.native(this.context).includes('libDexHelper')) {
          log(`strcmp(${this.s1}, ${this.s2})`);
          // log(Stack.native(this.context));
        }
      },
    });
  }
}

// const accessPtr = Module.findExportByName(null, 'access');
// if (accessPtr) {
//   log('[*] hooked access : ', accessPtr);
//   Interceptor.attach(accessPtr, {
//     onEnter: function (args) {
//       this.file = args[0].readUtf8String();
//     },
//     onLeave: function (retval) {
//       log('[+] access :', this.file, 'ret :', retval);
//       log(Stack.native(this.context));
//     },
//   });
// }

// const mprotectPtr = Module.findExportByName(null, 'mprotect');
// if (mprotectPtr) {
//   Interceptor.attach(mprotectPtr, {
//     onEnter: function (args) {
//       // if (!args[1].readUtf8String()?.includes('libart.so')) {
//         log(`>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> mprotectPtr`)
//       // }
//     },
//     onLeave: function (retval) {
//       // if (retval) {
//       //   log(`strstr retval ${retval}`)
//       // }
//     },
//   });
// }

// const dlopenPtr = Module.findExportByName(null, 'dlopen');
// if (dlopenPtr) {
//   log('[*] hooked dlopen : ', dlopenPtr);
//   Interceptor.attach(dlopenPtr, {
//     onEnter: function (args) {
//       this.libName = args[0].readUtf8String();
//     },
//     onLeave: function (retval) {
//       log('[*] dlopen :', this.libName, 'ret :', retval);
//     },
//   });
// }

// const dlsymPtr = Module.findExportByName(null, 'dlsym');
// if (dlsymPtr) {
//   Interceptor.attach(dlsymPtr, {
//     onEnter: function (args) {
//       this.handle = args[0];
//       this.funcName = args[1].readUtf8String();
//     },
//     onLeave: function (retval) {
//       log('[*] dlsym - handle :', this.handle, 'funcName :', this.funcName, 'ret :', retval);
//     },
//   });
// }
