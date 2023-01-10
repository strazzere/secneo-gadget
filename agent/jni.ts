import { log } from './logger';

const debug = false;

// https://cs.android.com/android/platform/superproject/+/master:bionic/libc/include/dlfcn.h;l=55-60
enum RTLD_FLAGS {
  RTLD_LOCAL = 0,
  RTLD_LAZY = 0x00001,
  RTLD_NOW = 0x00002,
  RTLD_NOLOAD = 0x00004,
  RTLD_GLOBAL = 0x00100,
  RTLD_NODELETE = 0x01000,
}

function parseFlags(flags: number) {
  let ret = '';
  const strings = Object.keys(RTLD_FLAGS);
  const values = Object.values(RTLD_FLAGS);

  values.forEach((value, index) => {
    if ((flags & Number(value)) !== 0) {
      if (ret.length > 0) {
        ret = ret.concat(' | ');
      }
      ret = ret.concat(strings[index]);
    }
  });

  if (ret === '') {
    return 'RTLD_LOCAL';
  }

  return ret;
}

// By hooking this call, we should be able to ensure that
// the shared library is loaded, so we can hook any (non-packed) functions
// such as JNI_onLoad
// https://cs.android.com/android/platform/superproject/+/master:external/cronet/base/android/linker/modern_linker_jni.cc;l=147-179
export function dlopenExtHook(targetLibrary: string, callback?: (context: CpuContext) => void) {
  const androidDlopenExtPtr = Module.findExportByName(null, 'android_dlopen_ext');
  if (androidDlopenExtPtr) {
    const listener = Interceptor.attach(androidDlopenExtPtr, {
      onEnter: function (args) {
        this.library = args[0].readUtf8String();
        this.flags = parseFlags(args[1].toInt32());
      },
      onLeave: function (retval) {
        log(` [+] androidDlopenExt("${this.library}", ${this.flags}, &dlextinfo) : ${retval}`);
        if (this.library.includes(targetLibrary)) {
          hookJniLoad(targetLibrary, callback);
          // We don't need to keep this listener around once it's been hit on what we want
          listener.detach();
        }
      },
    });
  }
}

function hookJniLoad(targetLibrary: string, callback?: (context: CpuContext) => void): void {
  const jniLoadPtr = Module.findExportByName(targetLibrary, 'JNI_OnLoad');
  if (!jniLoadPtr) {
    throw new Error(`No address was found for JNI_OnLoad for ${targetLibrary}`);
  }
  if (debug) {
    console.log(`Attaching to ${jniLoadPtr}`);
  }

  const listener = Interceptor.attach(jniLoadPtr, {
    onEnter: function (_args) {
      callback?.(this.context);
      // We likely could detach this, as a jni onload should not be fired more than once unless
      // some weirdness is going on?
      listener.detach();
    },
  });
}

// This was a targetted attempt at a different solution, it would not be wise to run
// them both at the same time?
// https://cs.android.com/android/platform/superproject/+/master:art/runtime/jni/java_vm_ext.h;l=106?ss=android%2Fplatform%2Fsuperproject
export function loadNativeLib(targetLibrary: string, callback?: (context: CpuContext) => void) {
  const loadNativeLibPtr = Module.findExportByName(
    'libart.so',
    '_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_',
  );
  if (loadNativeLibPtr) {
    Interceptor.attach(loadNativeLibPtr, {
      onEnter: function (_args) {
        // args[1] is a std::string which contains the library, but this is a bit
        // of an annoyance to parse correctly
        hookJniLoad(targetLibrary, callback);
      },
    });
  }
}
