import { log } from './logger';
import { Stack } from './stack';
import { hookDexHelper, secneoJavaHooks } from './secneo';
import { dlopenExtHook } from './jni';
import { hookCallFunction } from './linker';

// Oddly this is a string
const targetedAndroidVersion = '13';
if (Java.androidVersion !== targetedAndroidVersion) {
  log(
    `Unexpected Android version, this script may not work as expected, targeting ${targetedAndroidVersion} but found ${Java.androidVersion}`,
  );
}

log(`Attempting to work inside pid ${Process.id}`);

// To avoid the SIGILL from the openssl, though this doesn't seem to be the primary issue?
let replaced = false;
hookCallFunction('libdjibase.so', (_context, _functionName, _pointer) => {
  if (!replaced) {
    const OPENSSL_cpuid_setupPtr = Module.findExportByName('libdjibase.so', 'OPENSSL_cpuid_setup');
    if (OPENSSL_cpuid_setupPtr) {
      log(` [+] replacing OPENSSL_cpuid_setup @ ${OPENSSL_cpuid_setupPtr}`);
      try {
        const OPENSSL_cpuid_setup = new NativeFunction(OPENSSL_cpuid_setupPtr, 'void', ['void']);
        Interceptor.replace(
          OPENSSL_cpuid_setup,
          new NativeCallback(
            function () {
              log(` [*] Skipping OPENSSL_cpuid_setup`);
            },
            'void',
            ['void'],
          ),
        );
        replaced = true;
      } catch (error) {
        log(` [!] Unable to hook this attempt, likely not yet unpacked, will retry`);
      }
    }
  }
});

let hooked = false;
if (!hooked) {
  dlopenExtHook('libDexHelper.so', function (_context) {
    hooked = true;
    hookDexHelper();
    secneoJavaHooks();
  });
}

Process.setExceptionHandler(function (d) {
  const clean = Stack.getModuleInfo(d.address);
  console.log(`Exception caught : ${d} : (pc :${d.context.pc}) : ${d.address} : ${clean}`);
  log(Stack.native(d.context));

  return false;
});

log(`${hooked ? '(Re)l' : 'l'}oaded`);
