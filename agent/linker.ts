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
    return false;
  }

  // Targeting to find this function `bionic/linker/linker_soinfo.cpp`
  // call_function(const char* function_name __unused,
  //                        linker_ctor_function_t function,
  //                        const char* realpath __unused)
  // https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_soinfo.cpp;l=463;bpv=1
  return linker.enumerateSymbols().some((symbol) => {
    if (symbol.name.indexOf('call_function') >= 0) {
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
  if (!address) {
    return false;
  }

  Interceptor.attach(address, {
    onEnter: function (args) {
      const functionName = args[0].readCString();
      const functionPointer = args[1];
      const realPath = args[2].readCString();
      if (realPath && realPath.indexOf(targetLibrary) >= 0) {
        const moduleAddress = Module.findBaseAddress(targetLibrary);
        const truePointer = functionPointer.sub(moduleAddress ? moduleAddress : 0x0).sub(0x1);
        log(`[function name: ${functionName}, offset: 0x${truePointer}`);
        callback?.(truePointer);
      }
    },
  });

  return true;
}
