import { log } from './logger';
import { Stack } from './stack';
import { hookDexHelper, secneoJavaHooks, forceLoadClasses } from './secneo';
import { dlopenExtHook } from './jni';
import { hookCallFunction } from './linker';
import { antiDebug } from './anti';
import { getPackageName } from './dex';
import { processRelevantModules } from './elf';

// Oddly this is a string
const targetedAndroidVersion = '13';
if (Java.androidVersion !== targetedAndroidVersion) {
  log(
    `Unexpected Android version, this script may not work as expected, targeting ${targetedAndroidVersion} but found ${Java.androidVersion}`,
  );
} else {
  log(`Android version ${Java.androidVersion}`);
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
              Thread.sleep(1);
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
  const packagename = getPackageName();

  const hookFunctions = (anti: boolean) => {
    hooked = true;
    hookDexHelper(anti);
    // We don't actually need this for the purposes of doing any of the antidebug work
    // we just need to "slow down" execution for frida to catch the java hooks we want
    // which follow it
    // if (anti) {
    antiDebug();
    // }

    secneoJavaHooks();
    forceLoadClasses();
  };

  // Currently the pilot versions we have seen utilize a different version or style of
  // secneo, so we need to attach to the post fork'ed process
  if (packagename.includes('pilot')) {
    hookFunctions(false);
    processRelevantModules();
  } else {
    dlopenExtHook(
      'libDexHelper.so',
      function (_context) {
        send({
          event: 'dlopenExtHook',
          detail: 'Hit hook, attempting to set hooks inside lib',
        });
        hookFunctions(true);
      },
      function (_context) {
        // This appears to be too late to call the hook
        // secneoJavaHooks();
      },
    );
  }
}

Process.setExceptionHandler(function (d) {
  const clean = Stack.getModuleInfo(d.address);
  console.log(`Exception caught : ${d} : (pc :${d.context.pc}) : ${d.address} : ${clean}`);
  log(Stack.native(d.context));

  return false;
});

log(`Script ${hooked ? '(Re)l' : 'l'}oaded`);

send({
  event: 'loaded',
  detail: 'Initialized index loaded fully',
});
