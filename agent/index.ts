import { log } from './logger';
import { Stack } from './stack';

const debug = false;

const stack = new Stack();
const getStack = () => {
  log(stack.java());
};

// if (Java.available) {
//   if (debug) {
//     log('Java was available, attempting to create a thread and hook methods...');
//     Java.perform(() => {
//       const ThreadDef = Java.use('java.lang.Thread');
//       threadObj = ThreadDef.$new();
//     });
//   }

//   Java.perform(() => {
//     const usbManager = Java.use('android.hardware.usb.UsbManager');
//     usbManager.openAccessory.overload('android.hardware.usb.UsbAccessory').implementation = (
//       usbAccessory: NativePointerValue,
//     ) => {
//       if (debug) {
//         log(`usbManager.openAccessory(android.hardware.usb.UsbAccessory) called`);
//         stack.java();
//       }
//       const ret = usbManager.openAccessory.call(this, usbAccessory);
//       const parcelFileDescriptor = Java.cast(ret, Java.use('android.os.ParcelFileDescriptor'));

//       log(`***** usb accessory FD : ${parcelFileDescriptor} ${parcelFileDescriptor.getFd()}`);
//       accessoryFD = parcelFileDescriptor.getFd();
//       return parcelFileDescriptor;
//     };

//     if (debug) {
//       const usbAccessoryService = Java.use('dji.midware.usb.P3.UsbAccessoryService');
//       usbAccessoryService.sendmessage.overload(
//         'dji.midware.data.packages.P3.SendPack',
//       ).implementation = (sendPack: NativePointerValue) => {
//         const sendPackObject = Java.cast(
//           sendPack,
//           Java.use('dji.midware.data.packages.P3.SendPack'),
//         );
//         log(`usbAccessoryService.sendmessage(sendPack) called ${sendPackObject.toString()}`);
//         log(`cmdSet : ${sendPackObject.cmdSet.value} cmdId:  ${sendPackObject.cmdId.value}`);
//         stackTraceOutsideJava();
//         usbAccessoryService.sendmessage.call(this, sendPack);
//       };
//     }
//   });
// } else {
//   console.log('Java not available - unable to set classloader, very likely everything will fail');
// }

// const libcWrite = Module.findExportByName('libc.so', 'write');
// if (libcWrite) {
//   Interceptor.attach(libcWrite, {
//     onEnter: function (args) {
//       if (accessoryFD && args[0].toInt32() === accessoryFD) {
//         //                                                    id set
//         // 55 cc 49 57 0e 00 00 00 55 0e 04 66 02 03 01 00 40 03 fe 00 65 e9
//         const cmdSet = args[1].add(0x11).readU8();
//         const cmdId = args[1].add(0x12).readU8();

//         if (cmdSet === 0 && cmdId && (cmdId === 0x4f || cmdId === 0xff)) {
//           if (debug) {
//             const size = args[2].toInt32();
//             log(`********************* Offending packet found`);
//             log(`cmdSet : 0x${cmdSet.toString(16)} cmdId : 0x${cmdId.toString(16)}`);
//             log(hexdump(args[1], { length: size }));
//             log(
//               Thread.backtrace(this.context, Backtracer.ACCURATE)
//                 .map(DebugSymbol.fromAddress)
//                 .join('\n') + '\n',
//             );
//           }
//           args[1].add(0x12).writeU8(0x5a);
//         }
//       }
//     },
//   });
// }

console.log(`Reloaded`);
