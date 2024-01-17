import { log } from './logger.ts';
import { Stack } from './stack.ts';
import { hookDexHelper, secneoJavaHooks, forceLoadClasses } from './secneo.ts';
import { dlopenExtHook } from './jni.ts';
import { hookCallFunction } from './linker.ts';
import { antiDebug } from './anti.ts';
import { getPackageName } from './dex.ts';
import { processRelevantModules } from './elf.ts';

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
  let packagename = getPackageName();
  if (!packagename) {
    log(` [!] Unable to obtain package name, likely everything will break`);
    packagename = 'Unknown';
  }
  log(` [+] Hooking inside the package : ${packagename}`);

  const hookFunctions = (anti: boolean) => {
    hooked = true;
    hookDexHelper(anti, true, true);
    // We don't actually need this for the purposes of doing any of the antidebug work
    // we just need to "slow down" execution for frida to catch the java hooks we want
    // which follow it
    if (anti) {
      antiDebug();
    }

    if (packagename && !packagename.includes('pilot')) {
      secneoJavaHooks();
    }

    forceLoadClasses();
  };

  // Currently the pilot versions we have seen utilize a different version or style of
  // secneo, so we need to attach to the post fork'ed process
  if (packagename && packagename.includes('pilot')) {
    hookFunctions(false);

    // This is a great way to reveal where the hooking engine is working
    // processRelevantModules();
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
