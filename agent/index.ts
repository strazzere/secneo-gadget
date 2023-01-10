import { log } from './logger';
import { Stack } from './stack';
import { hookLifeCycles } from './lifecycle';
import { antiDebug } from './anti';
import { hookDexHelper, secneoJavaHooks, antiDebugThreadReplacer } from './secneo';
import { inotifyHooks } from './inotify';
import { dlopenExtHook } from './jni';

const stack = new Stack();
const _getStack = () => {
  log(stack.java());
};

// Oddly this is a string
const targetedAndroidVersion = '13';
if (Java.androidVersion !== targetedAndroidVersion) {
  log(
    `Unexpected Android version, this script may not work as expected, targeting ${targetedAndroidVersion} but found ${Java.androidVersion}`,
  );
}

log(`Attempting to work inside pid ${Process.id}`);

let hooked = false;
const targetLibrary = 'libDexHelper.so';

antiDebugThreadReplacer();
dlopenExtHook(targetLibrary, function (_context) {
  antiDebug();
  secneoJavaHooks();
  hookLifeCycles();
  inotifyHooks();
  hookDexHelper();
});

Process.setExceptionHandler(function (d) {
  const affectedModule = Process.findModuleByAddress(d.address);
  console.log(
    `Exception caught : ${d} : (pc :${d.context.pc}) : ${d.address} : ${affectedModule?.base.sub(
      d.address,
    )}`,
  );
  // log(Stack.native(d.context));
  return false;
});

log(`${hooked ? '(Re)l' : 'l'}oaded`);
