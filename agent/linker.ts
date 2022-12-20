import { log } from './logger';

export function hookCallFunction(targetLibrary: string, callback?: () => void): boolean {
  const linkerModuleName = Process.pointerSize === 4 ? 'linker' : 'linker64'
  const linker = Process.findModuleByName(linkerModuleName)

  if (!linker) {
    return false;
  }

  return linker.enumerateSymbols().some((symbol) => {
    if (symbol.name.indexOf('call_function') >= 0) {
      return hookFunction(targetLibrary, symbol.address, callback);
    }
    return false;
  });
}

function hookFunction(
  targetLibrary: string,
  address: NativePointer,
  callback?: () => void,
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
        log(
          `[function name: ${functionName}, offset: 0x${functionPointer
            .sub(moduleAddress ? moduleAddress : 0x0)
            .sub(0x1)}`,
        );
        callback?.();
      }
    },
  });

  return true;
}
