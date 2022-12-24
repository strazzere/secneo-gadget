import { log } from './logger';

/**
 * @param targetLibrary the library to target for early hooking
 * @param callback which should provide a NativePointer for the early functions
 * @returns
 */
export function hookCallFunction(
  targetLibrary: string,
  callback?: (pointer: NativePointer) => void,
): boolean {
  const linkerModuleName = Process.pointerSize === 4 ? 'linker' : 'linker64';
  const linker = Process.findModuleByName(linkerModuleName);

  if (!linker) {
    log(Process.enumerateModules());
    return false;
  }

  log(`got linker;`);
  log(JSON.stringify(linker));
  // We actually target the call_array as the call_function gets inlined too often
  // static inline void call_array(const char* array_name __unused, F* functions, size_t count,
  //                                bool reverse, const char* realpath) {
  // Targeting to find this function `bionic/linker/linker_soinfo.cpp`
  // call_function(const char* function_name __unused,
  //                        linker_ctor_function_t function,
  //                        const char* realpath __unused)
  // https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_soinfo.cpp;l=488;bpv=1
  return linker.enumerateSymbols().some((symbol) => {
    if (symbol.name.indexOf('call_array') >= 0) {
      log(`Found function to hook which is symbol ${symbol}`);
      return hookFunction(targetLibrary, symbol.address, callback);
    }
    return false;
  });
}

/**
 * @param targetLibrary the library to target for early hooking
 * @param address
 * @param callback which should provide a NativePointer for the early functions
 * @returns
 */
function hookFunction(
  targetLibrary: string,
  address: NativePointer,
  callback?: (pointer: NativePointer) => void,
): boolean {
  log(`Attempting to hook function...`);
  if (!address) {
    return false;
  }

  Interceptor.attach(address, {
    onEnter: function (args) {
      const arrayName = args[0].readCString();
      const functionPointerArray = args[1];
      const count = args[2];
      const reverse = args[3];
      const realPath = args[4].readCString();
      if (realPath && realPath.indexOf(targetLibrary) >= 0) {
        const moduleAddress = Module.findBaseAddress(targetLibrary);
        const truePointer = functionPointerArray.sub(moduleAddress ? moduleAddress : 0x0).sub(0x1);
        log(`[array name: ${arrayName}, count: ${count} offset: 0x${truePointer}`);
        callback?.(truePointer);
      }
    },
  });

  log(`done`);

  return true;
}

// Look into these functions for catching load
// 0x6f9d59e2c8 libart.so!_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_+0xce4
// 0x6f91e920e4 libopenjdkjvm.so!JVM_NativeLoad+0x1a0
