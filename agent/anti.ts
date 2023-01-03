import { log } from './logger';
import { Stack } from './stack';

const debug = true;

export function antiDebug() {
  javaHooks();
  connectHook();
  unlinkHook();
  exitHook();
  forkHook();
  ptraceHook();
  tracerHook();
  hookKill();
  if (debug) {
    log(` [+] finished hooking anti debug methods`);
  }
}

function javaHooks() {
  Java.performNow(() => {
    javaSystemExit();
    javaProcessKill();
    javaActivityFinish();
    javaActivityDestroy();
  });
}

function javaSystemExit() {
  const system = Java.use('java.lang.System');
  system.exit.overload('int').implementation = function (pid: number) {
    log(` [!] java.lang.System.exit(${pid})`);
  };
}

function javaProcessKill() {
  const process = Java.use('android.os.Process');
  process.killProcess.overload('int').implementation = function (pid: number) {
    log(` [!] android.os.Process.KillProcess(${pid})`);
  };
}

function javaActivityFinish() {
  const activity = Java.use('android.app.Activity');
  activity.finishActivity.overload('int').implementation = function () {
    log(` [!] android.app.Activity.FinishActivity()`);
  };
}

function javaActivityDestroy() {
  Java.choose('android.app.Activity', {
    onMatch: function (instance) {
      instance.onDestroy.overload().implementation = function () {
        log(` [!] android.app.Activity.onDestroy()`);
      };
    },
    onComplete: function () {
      // needed?
    },
  });
}

function connectHook() {
  const connectPtr = Module.findExportByName('libc.so', 'connect');
  if (connectPtr) {
    if (debug) {
      log(` [+] antidebug : connect anti frida hooked @ ${connectPtr}`);
    }
    Interceptor.attach(connectPtr, {
      onEnter: function (args) {
        const memory = args[1].readByteArray(64);
        if (memory) {
          const buffer = new Uint8Array(memory);
          const fridaPort = new Uint8Array(Buffer.from('69a27f000001', 'hex'));
          if (Buffer.compare(buffer.slice(2, 7), fridaPort) === 0) {
            this.fridaDetection = true;
            log(` [!] connect : app is attempting to detect frida`);
            log(Stack.native(this.context));
          }
        } else {
          log(` [!] connect : memory unable to be read?`);
        }
      },
      onLeave: function (retval) {
        if (this.fridaDetection) {
          retval.replace(ptr(-1));
          log(' [!] frida detection Bypassed');
        }
      },
    });
  }
}

function unlinkHook() {
  const unlinkPtr = Module.findExportByName(null, 'unlink');
  if (unlinkPtr) {
    if (debug) {
      log(` [+] antidebug : unlink hooked @ ${unlinkPtr}`);
    }
    Interceptor.attach(unlinkPtr, {
      onEnter: function (args) {
        log(` [!] unlink - ${args[0].readUtf8String()}`);
        log(Stack.native(this.context));
      },
    });
  }
}

function exitHook() {
  const exitPtr = Module.getExportByName(null, 'exit');
  if (exitPtr) {
    if (debug) {
      log(` [+] antidebug : exit hooked @ ${exitPtr}`);
    }
    Interceptor.attach(exitPtr, {
      onEnter: function (_args) {
        log(` [!] exit`);
        log(Stack.native(this.context));
      },
    });
  }
}

function forkHook() {
  const forkPtr = Module.findExportByName(null, 'fork');
  if (forkPtr) {
    if (debug) {
      log(` [+] antidebug : fork hooked @ ${forkPtr}`);
    }
    Interceptor.attach(forkPtr, {
      onLeave: function (retval) {
        const pid = parseInt(retval.toString(16), 16);
        log(` [!] fork : child process pid ${pid}`);
      },
    });
  }
}

function ptraceHook() {
  const ptracePtr = Module.findExportByName(null, 'ptrace');
  if (ptracePtr) {
    if (debug) {
      log(` [+] antidebug : ptrace hooked @ ${ptracePtr}`);
    }
    Interceptor.attach(ptracePtr, {
      onLeave: function (retval) {
        log(` [!] ptrace : asserting to app that ptrace connection worked`);
        retval.replace(ptr(0));
      },
    });
  }
}

function tracerHook() {
  const fgetsPtr = Module.findExportByName('libc.so', 'fgets');
  if (fgetsPtr) {
    if (debug) {
      log(` [+] antidebug : tracer hooking fgets @ ${fgetsPtr}`);
    }
    const fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(
      fgetsPtr,
      new NativeCallback(
        function (stream, size, fp) {
          const retval = fgets(stream, size, fp);
          const str = stream.readUtf8String();
          if (str && str.indexOf('TracerPid:') > -1) {
            stream.writeUtf8String('TracerPid:\t0');
            log(` [!] tracer : changing fgets buffer to have no tracer pid`);
          }
          return retval;
        },
        'pointer',
        ['pointer', 'int', 'pointer'],
      ),
    );
  }
}

function hookKill() {
  const killPtr = Module.findExportByName(null, 'kill');
  if (killPtr) {
    if (debug) {
      log(` [+] antidebug : kill hooked @ ${killPtr}`);
    }
    Interceptor.replace(
      killPtr,
      new NativeCallback(
        (pid, sig) => {
          log(`[+] kill : ${pid} with ${sig}`);
          log(`IGNORING KILL`);
          return 0;
        },
        'int',
        ['int', 'int'],
      ),
    );
  }
}
