import Java from "frida-java-bridge";
import { log } from "./logger";
import { Stack } from "./stack";

const stack = new Stack();
const getStack = () => {
  log(stack.java());
};

export function hookLifeCycles() {
  log(` [+] hooking lifecycle code`);
  hookApplicationStates();
  hookActivityStates();
  log(` [+] done hooking lifecycle code`);
}

export function hookApplicationStates() {
  Java.performNow(() => {
    const application = Java.use(`android.app.Application`);
    application.onCreate.implementation = function () {
      log(` > onCreate called`);
      getStack();
      this.onCreate();
    };

    application.onTerminate.implementation = function () {
      log(` > onTerminate called`);
      getStack();
      this.onTerminate();
    };
  });
}

export function hookActivityStates() {
  Java.performNow(() => {
    const activity = Java.use(`android.app.Activity`);
    activity.onResume.implementation = function () {
      log(` > resume called`);
      getStack();
      this.onResume();
    };

    activity.onDestroy.implementation = function () {
      log(` > destroy called`);
      getStack();
      this.onDestroy();
    };

    activity.onCreate.overload("android.os.Bundle").implementation = function (
      bundle: Java.Wrapper<object>,
    ) {
      log(` > create called`);
      getStack();
      this.onCreate(bundle);
    };

    activity.onStart.implementation = function () {
      log(` > start called`);
      getStack();
      this.onStart();
    };

    activity.onPause.implementation = function () {
      log(` > pause called`);
      getStack();
      this.onPause();
    };

    activity.onStop.implementation = function () {
      log(` > stop called`);
      getStack();
      this.onStop();
    };

    activity.onRestart.implementation = function () {
      log(` > restart called`);
      getStack();
      this.onRestart();
    };
  });
}
