import { log } from "./logger";

const debug = true;

export function memoryHooks() {
  if (debug) {
    log(` [*] hooking memory methods`);
  }

  hookMemcpy();
  hookMprotect();

  if (debug) {
    log(` [+] finished hooking memory methods`);
  }
}

const minMemCpySizeNotify = 8;
const trigger = false;

function hookMemcpy() {
  const memcpyPtr = Module.findGlobalExportByName("memcpy");
  if (memcpyPtr) {
    if (debug) {
      log(` [+] memory : memcpy hooked @ ${memcpyPtr}`);
    }

    Interceptor.attach(memcpyPtr, {
      onEnter: (args) => {
        if (trigger) {
          if (args[2].toInt32() >= minMemCpySizeNotify) {
            log(`[*] memcpy(${args[0]}, ${args[1]}, ${args[2].toInt32()}`);
          }
        }
      },
    });
  }
}

// From https://cs.android.com/android/platform/superproject/+/master:art/libartbase/base/mman.h;l=24
enum MPROTECT_FLAGS {
  PROT_READ = 0x1,
  PROT_WRITE = 0x2,
  PROT_EXEC = 0x4,
  PROT_NONE = 0x0,

  // eslint-disable-next-line @typescript-eslint/no-duplicate-enum-values
  MAP_SHARED = 0x01,
  // eslint-disable-next-line @typescript-eslint/no-duplicate-enum-values
  MAP_PRIVATE = 0x02,

  MAP_FIXED = 0x10,
  MAP_ANONYMOUS = 0x20,
}

function parseFlags(flags: number) {
  let ret = "";
  const strings = Object.keys(MPROTECT_FLAGS);
  const values = Object.values(MPROTECT_FLAGS);

  values.forEach((value, index) => {
    if ((flags & Number(value)) !== 0) {
      if (ret.length > 0) {
        ret = ret.concat(" | ");
      }
      ret = ret.concat(strings[index]);
    }
  });

  if (ret === "") {
    return "PROT_NONE";
  }

  return ret;
}

function hookMprotect() {
  const mprotectPtr = Module.findGlobalExportByName("mprotect");
  if (mprotectPtr) {
    if (debug) {
      log(` [+] memory : mprotect hooked @ ${mprotectPtr}`);
    }

    Interceptor.attach(mprotectPtr, {
      onEnter: function (args) {
        this.address = args[0];
        this.length = args[1].toInt32();
        this.protection = parseFlags(args[2].toInt32());
      },
      onLeave: function (retval) {
        if (retval.toInt32() === 0) {
          log(
            ` [+] mprotect(${this.address}, ${this.length}, ${this.protection}) : success`,
          );
        } else {
          log(
            ` [-] mprotect(${this.address}, ${this.length}, ${this.protection}) : failed`,
          );
        }
      },
    });
  }
}
