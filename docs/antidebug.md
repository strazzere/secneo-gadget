# Anti-debug

Seeing crashes like this:
```
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/flame/flame:13/TP1A.220624.014/8819323:user/release-keys'
Revision: 'MP1.0'
ABI: 'arm64'
Timestamp: 2022-12-26 14:51:12.181246212-0800
Process uptime: 1120s
Cmdline: dji.go.v5
pid: 11716, tid: 11783, name: dji.go.v5  >>> dji.go.v5 <<<
uid: 10191
signal 11 (SIGSEGV), code 128 (SI_KERNEL), fault addr 0x0000000000000000
    x0  0000000000000785  x1  00000070489287b4  x2  000000000000000a  x3  8c2e6d6000000000
    x4  0000000000000000  x5  0e14000400000000  x6  000000000400140e  x7  6466606f2e353036
    x8  00000000b6a287d5  x9  0000000000000785  x10 0101010101010101  x11 0000000000000025
    x12 000000703ce46274  x13 0000000000000002  x14 0000000000000010  x15 000000735fb36662
    x16 000000735fbd6380  x17 000000735fbb2dd0  x18 000000703ce469c0  x19 00000070489ca000
    x20 0000000000002dc4  x21 00000070489a4b9c  x22 b4000070d9dc77f0  x23 000000703ce46c38
    x24 0000000000000006  x25 00000070489d4de0  x26 000000000000000a  x27 000000000000001e
    x28 b4000070d9dc77f0  x29 000000703ce46bd0
    lr  0000000000000000  sp  0000000000000000  pc  0000000000000785  pst 0000000080000000

backtrace:
      #00 pc 0000000000000785  <unknown>
      #01 pc 0000000000000000  <unknown>
```

They are caused by the following "bad" code which is only tripped when a debugger is attached (signals being caught);
```
loc_9D7CC               ; jumptable 000000000009D7B0 case 15
MOV             X0, #0
MOV             SP, X0  ; nuke SP
MOV             X30, X0 ; nuke PC
MOV             W0, #0xB6A287D5
MOV             X8, X0
MOV             X0, #0x785
MOV             X9, X0
BR              X0      ; call bad address 0x785
```


Extra threads being spun up to detect debuggers;
```
 ======= >pthread_create : 703e2aac5c
0x703e2b365c libDexHelper.so!p85F0BB1FF98C67C7C92303B60ECE536C+0x12c
0x703e247f14 libDexHelper.so!JNI_OnLoad+0x3be4
0x70c6f8a444 libart.so!_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_+0x600
0x70bb2e017c libopenjdkjvm.so!JVM_NativeLoad+0x1a4
0x7022f940 boot.oat!0x93940
0x7022f940 boot.oat!0x93940
```

Nuke it via;
```
    const antiDebugThreadAddresses = [
      0x9ec5c, 0xaa97c, 0x9d73c, 0xe3fd0,
      // 0x9d030,
      // 0xe3fcc
    ];

    antiDebugThreadAddresses.forEach((address, index) => {
      Interceptor.replace(
        dexBase.add(address),
        new NativeCallback(
          function () {
            log(`===> skipping anti debug thread ${index}...`);
            return;
          },
          'void',
          ['void'],
        ),
      );
    });
```

Fake functions that cause seemingly valid crashes;

```
12-27 16:40:37.602 29696 29696 F DEBUG   : *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
12-27 16:40:37.602 29696 29696 F DEBUG   : Build fingerprint: 'google/flame/flame:13/TP1A.220624.014/8819323:user/release-keys'
12-27 16:40:37.602 29696 29696 F DEBUG   : Revision: 'MP1.0'
12-27 16:40:37.602 29696 29696 F DEBUG   : ABI: 'arm64'
12-27 16:40:37.602 29696 29696 F DEBUG   : Timestamp: 2022-12-27 16:40:37.114612084-0800
12-27 16:40:37.602 29696 29696 F DEBUG   : Process uptime: 3s
12-27 16:40:37.602 29696 29696 F DEBUG   : Cmdline: dji.go.v5
12-27 16:40:37.602 29696 29696 F DEBUG   : pid: 29670, tid: 29670, name: dji.go.v5  >>> dji.go.v5 <<<
12-27 16:40:37.602 29696 29696 F DEBUG   : uid: 10191
12-27 16:40:37.602 29696 29696 F DEBUG   : signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x006e756843647335
12-27 16:40:37.602 29696 29696 F DEBUG   :     x0  0000007044d5e000  x1  0000007044c912f8  x2  000000735fbe454c  x3  0000007ff0a7d0f8
12-27 16:40:37.602 29696 29696 F DEBUG   :     x4  0000000000000400  x5  000000000000aa88  x6  3063383230666637  x7  61306666372d3030
12-27 16:40:37.602 29696 29696 F DEBUG   :     x8  153a224e3e4905f2  x9  153a224e3e4905f2  x10 00000000000073e6  x11 0000000000000005
12-27 16:40:37.602 29696 29696 F DEBUG   :     x12 000000000000aef5  x13 2020202020202020  x14 0000120400000000  x15 0000000000000062
12-27 16:40:37.602 29696 29696 F DEBUG   :     x16 0000000000000001  x17 000000735fbc8694  x18 0000000000000004  x19 00000000000004b0
12-27 16:40:37.602 29696 29696 F DEBUG   :     x20 0000000000000000  x21 0000007044d37668  x22 6b6e756843647315  x23 0000000000000000
12-27 16:40:37.602 29696 29696 F DEBUG   :     x24 0000007ff0a7d308  x25 0000007ff0a7d258  x26 0000007ff0a7d268  x27 0000007ff0a7d288
12-27 16:40:37.602 29696 29696 F DEBUG   :     x28 0000007ff0a7d260  x29 0000007ff0a7d180
12-27 16:40:37.602 29696 29696 F DEBUG   :     lr  0000007044c916a8  sp  0000007ff0a7d180  pc  0000007044c913f8  pst 0000000080000000
12-27 16:40:37.602 29696 29696 F DEBUG   : backtrace:
12-27 16:40:37.602 29696 29696 F DEBUG   :       #00 pc 00000000000723f8  /data/app/~~MqRQliVXJBkO4KgqEB3Ijw==/dji.go.v5-W42ZSs3YC6RI90Pdm5Kqqw==/lib/arm64/libDexHelper.so
```

Have to nuke them via;
```
  // This is seemingly an anti-debug trap so we can just patch it out and skip it for the time being
  // _Z33p9612F93FF34AFA81C8ABDBB91765B9A6v
  const _Z33p9612F93FF34AFA81C8ABDBB91765B9A6v = Module.findExportByName(
    'libDexHelper.so',
    '_Z33p9612F93FF34AFA81C8ABDBB91765B9A6v',
  );
  if (_Z33p9612F93FF34AFA81C8ABDBB91765B9A6v) {
    Interceptor.replace(
      _Z33p9612F93FF34AFA81C8ABDBB91765B9A6v,
      new NativeCallback(
        function () {
          log('skipping...');
          return;
        },
        'void',
        ['void'],
      ),
    );
  }
```