import { log } from './logger';
import { Stack } from './stack';

const stack = new Stack();
const getStack = () => {
  log(stack.java());
};

export function hookActivityStates() {
  Java.perform(function () {
    log(`hooking java code`);
    const activity = Java.use(`android.app.Activity`);
    activity.onResume.implementation = function () {
      log(`resume called`);
      getStack();
      this.onResume();
    };

    activity.onDestroy.implementation = function () {
      log(`destroy called`);
      getStack();
      this.onDestroy();
    };

    activity.onCreate.implementation = function () {
      log(`create called`);
      getStack();
      this.onCreate();
    };

    activity.onStart.implementation = function () {
      log(`start called`);
      getStack();
      this.onStart();
    };

    activity.onPause.implementation = function () {
      log(`pause called`);
      getStack();
      this.onPause();
    };

    activity.onStop.implementation = function () {
      log(`stop called`);
      getStack();
      this.onStop();
    };

    activity.onRestart.implementation = function () {
      log(`restart called`);
      getStack();
      this.onRestart();
    };
    log(`dont hooking java code`);
  });
}
