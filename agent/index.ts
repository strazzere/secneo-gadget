import { log } from './logger';
import { Stack } from './stack';
import { hookCallFunction } from './linker';
import { hookLifeCycles } from './lifecycle';
import { antiDebug } from './anti';
import { hookDexHelper, secneoJavaHooks } from './secneo';
import { inotifyHooks } from './inotify';
import { memoryHooks } from './mem';

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

Process.setExceptionHandler(function (d) {
  console.log(`Exception caught : ${d} : ${d.context.pc} : ${d.address}`);
  log(Stack.native(d.context));
  return false;
});

log(`Calling hookCallFunction`);
let hooking = false;
const hookedStuff = hookCallFunction('libDexHelper.so', (_context, functionName, pointer) => {
  log(`Hit function call back for hookCallFunction for ${functionName} and value is ${pointer}`);
  // There is likely to never be anything but a native stack available at this point
  // log(Stack.native(context))
  if (!hooked && !hooking) {
    hooking = true;
    antiDebug();
    secneoJavaHooks();
    hookLifeCycles();
    inotifyHooks();
    memoryHooks();
    hookDexHelper();
    hooked = true;
  }
});

log(`${hooked ? '(Re)l' : 'l'}oaded : ${hookedStuff}`);
