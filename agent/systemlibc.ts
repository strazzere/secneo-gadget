import { log } from './logger';
import { Stack } from './stack';

const debug = true;

export function systemlibcHooks() {
  if (debug) {
    log(` [*] hooking generic system/libc methods`);
  }

  openHook();
  fopenHook();
  strcmpHook();
  dlopenHook();
  dlsymHook();
  readlinkHook()
  sleepHook()
  timeHook()

  if (debug) {
    log(` [+] finished hooking generic system/libc methods`);
  }
}

function timeHook() {
  const timePtr = Module.findExportByName(null, 'time');
  if (timePtr) {
    log('[*] hooked time : ', timePtr);
    Interceptor.attach(timePtr, {
      onEnter: function (_args) {
        log(`[*] time via ${Stack.getModuleInfo(this.returnAddress)}`);
      },
    });
  }
}

function sleepHook() {
  const sleepPtr = Module.findExportByName('libc.so', 'sleep');
  if (sleepPtr) {
    log('[*] hooked sleep : ', sleepPtr);
    Interceptor.attach(sleepPtr, {
      onEnter: function (_args) {
        log(`[*] sleep via ${Stack.getModuleInfo(this.returnAddress)}`);
      },
    });
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
        log(Stack.native(this.context));
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

function dlopenHook() {
  const dlopenPtr = Module.findExportByName(null, 'dlopen');
  if (dlopenPtr) {
    log(`[*] hooked dlopen @ ${dlopenPtr}`);
    Interceptor.attach(dlopenPtr, {
      onEnter: function (args) {
        this.libName = args[0].readUtf8String();
      },
      onLeave: function (retval) {
        log(`[*] dlopen(${this.libName}) : ${retval}`);
      },
    });
  }
}

function dlsymHook() {
  const dlsymPtr = Module.findExportByName(null, 'dlsym');
  if (dlsymPtr) {
    log(`[*] hooked dlsym @ ${dlsymPtr}`);
    Interceptor.attach(dlsymPtr, {
      onEnter: function (args) {
        this.handle = args[0];
        this.funcName = args[1].readUtf8String();
      },
      onLeave: function (retval) {
        log(`[*] dlsym(${this.handle}, "${this.funcName}") : ${retval}`);
        // log(` via ${Stack.getModuleInfo(this.returnAddress)}`)
      },
    });
  }
}

function readlinkHook() {
  const dlsymPtr = Module.findExportByName(null, 'readlink');
  if (dlsymPtr) {
    log(`[*] hooked readlink @ ${dlsymPtr}`);
    Interceptor.attach(dlsymPtr, {
      onEnter: function (args) {
        this.link = args[0].readUtf8String()
        this.buff = args[1]
      },
      onLeave: function (retval) {
        if (retval > ptr(0)) {
          log(`[*] readlink("${this.link}") : ${this.buff.readUtf8String()} : ${Stack.getModuleInfo(this.returnAddress)}`);
        }
      }
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