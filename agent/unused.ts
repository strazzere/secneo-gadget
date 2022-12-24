import { log } from './logger';
import { Stack } from './stack';

const systemPropertyGetPtr = Module.findExportByName(null, '__system_property_get');
if (systemPropertyGetPtr) {
  Interceptor.attach(systemPropertyGetPtr, {
    onEnter: function (args) {
      this.name = args[0].readUtf8String();
      if (args[1]) {
        this.value = args[1].readUtf8String();
      } else {
        this.value = null;
      }
    },
    onLeave: function (retval) {
      log(`__system_property_get("${this.name}", value=${this.value} ) : ${retval}`);
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
    onLeave: function (retval) {
      log(Stack.native(this.context));
    },
  });
}

// Can only be hooked after dex helper is unpacked
const xorStuff = Module.findBaseAddress('libDexHelper.so')?.add(0x18220);
if (xorStuff) {
  Interceptor.attach(xorStuff, {
    onEnter: function (args) {
      this.string = args[0];
    },
    onLeave: function (retval) {
      log(`xorStuff done - ${this.string.readUtf8String()}`);
      log(Stack.native(this.context));
    },
  });
}

const openPtr = Module.findExportByName(null, 'open');
if (openPtr) {
  Interceptor.attach(openPtr, {
    onEnter: function (args) {
      const fileName = args[0].readUtf8String();
      log(`[*] open - ${fileName}`);
    },
    onLeave: function (retval) {
      log(Stack.native(this.context));
    },
  });
}
