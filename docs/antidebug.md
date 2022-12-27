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