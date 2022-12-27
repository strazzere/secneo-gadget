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

// Can only be hooked after dex helper is unpacked
const dexBase = Module.findBaseAddress('libDexHelper.so')
const xorStuff = Module.findBaseAddress('libDexHelper.so')?.add(0x18220);
if (xorStuff) {
  Interceptor.attach(xorStuff, {
    onEnter: function (args) {
      this.string = args[0];
    },
    onLeave: function (_retval) {
      log(`xorStuff - "${this.returnAddress.sub(dexBase ? dexBase.add(0x4) : 0x4)}": "${this.string.readUtf8String()}",`);
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
    onLeave: function (_retval) {
      log(Stack.native(this.context));
    },
  });
}

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
        log(Stack.native(this.context));
      }
    },
  });
}
