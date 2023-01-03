// const fopenPtr = Module.findExportByName(null, 'fopen');
// if (fopenPtr) {
//   Interceptor.attach(fopenPtr, {
//     onEnter: function (args) {
//       const fileName = args[0].readUtf8String();
//       const mode = args[1].readUtf8String();
//       log(`[*] fopen - ${fileName} with mode ${mode}`);
//       log(Stack.native(this.context));
//     },
//     onLeave: function (_retval) {
//     },
//   });
// }

// const accessPtr = Module.findExportByName(null, 'access');
// if (accessPtr) {
//   log('[*] hooked access : ', accessPtr);
//   Interceptor.attach(accessPtr, {
//     onEnter: function (args) {
//       this.file = args[0].readUtf8String();
//     },
//     onLeave: function (retval) {
//       log('[+] access :', this.file, 'ret :', retval);
//       log(Stack.native(this.context));
//     },
//   });
// }

// const mprotectPtr = Module.findExportByName(null, 'mprotect');
// if (mprotectPtr) {
//   Interceptor.attach(mprotectPtr, {
//     onEnter: function (args) {
//       // if (!args[1].readUtf8String()?.includes('libart.so')) {
//         log(`>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> mprotectPtr`)
//       // }
//     },
//     onLeave: function (retval) {
//       // if (retval) {
//       //   log(`strstr retval ${retval}`)
//       // }
//     },
//   });
// }
