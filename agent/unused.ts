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
const dexBase = Module.findBaseAddress('libDexHelper.so');
const xorStuff = Module.findBaseAddress('libDexHelper.so')?.add(0x18220);
if (xorStuff) {
  Interceptor.attach(xorStuff, {
    onEnter: function (args) {
      this.string = args[0];
    },
    onLeave: function (_retval) {
      log(
        `xorStuff - "${this.returnAddress.sub(
          dexBase ? dexBase.add(0x4) : 0x4,
        )}": "${this.string.readUtf8String()}",`,
      );
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
