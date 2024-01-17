import { log } from './logger.ts';

const debug = false;

/**
 * @param targetLibrary the library to target for early hooking
 * @param callback which should provide a NativePointer for the early functions
 * @returns
 */
export function hookCallFunction(
  targetLibrary: string,
  callback?: (context: CpuContext, functionName: string, pointer: NativePointer) => void,
): boolean {
  const linkerModuleName = Process.pointerSize === 4 ? 'linker' : 'linker64';
  const linker = Process.findModuleByName(linkerModuleName);

  if (!linker) {
    return false;
  }

  if (debug) {
    log(`got linker;`);
    log(JSON.stringify(linker));
  }
  // We may actually need to target the call_array as the call_function gets inlined too often
  // static inline void call_array(const char* array_name __unused, F* functions, size_t count,
  //                                bool reverse, const char* realpath) {
  // Targeting to find this function `bionic/linker/linker_soinfo.cpp`
  // call_function(const char* function_name __unused,
  //                        linker_ctor_function_t function,
  //                        const char* realpath __unused)
  // https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_soinfo.cpp;l=475;bpv=1
  return linker.enumerateSymbols().some((symbol) => {
    if (symbol.name.indexOf('call_function') >= 0) {
      if (debug) {
        log(`Found function to hook which is symbol ${JSON.stringify(symbol)}`);
      }
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
  callback?: (context: CpuContext, functionName: string, pointer: NativePointer) => void,
): boolean {
  if (!address) {
    return false;
  }

  Interceptor.attach(address, {
    onEnter: function (args) {
      const functionName = args[0].readCString();
      const functionAddress = args[1];
      const realPath = args[2].readCString();
      if (realPath && realPath.indexOf(targetLibrary) >= 0) {
        const moduleAddress = Module.findBaseAddress(targetLibrary);
        const truePointer = functionAddress.sub(moduleAddress ? moduleAddress : 0x0).sub(0x1);
        if (debug) {
          log(
            `[call_function name: ${functionName}, offset: ${truePointer}, realpath : ${realPath}`,
          );
        }
        callback?.(this.context, functionName ? functionName : 'NO_NAME', truePointer);
      }
    },
  });

  return true;
}
