//  class2_field1_ = GetArtField("mypackage/packagea/Class2", "field1", "I");
//   class2_method1_ = GetArtMethod("mypackage/packagea/Class2", "method1", "()V");
//   class2_method1_i_ = GetArtMethod("mypackage/packagea/Class2", "method1", "(I)V");
//   class3_field1_ = GetArtField("mypackage/packageb/Class3", "field1", "I");
//   class3_method1_ = GetArtMethod("mypackage/packageb/Class3", "method1", "()V");
//   class3_method1_i_ = GetArtMethod("mypackage/packageb/Class3", "method1", "(I)V");
// }

// ArtMethod* GetArtMethod(const char* class_name, const char* name, const char* signature) {
//   JNIEnv* env = Thread::Current()->GetJniEnv();
//   jclass klass = env->FindClass(class_name);
//   jmethodID method_id = env->GetMethodID(klass, name, signature);
//   ArtMethod* art_method = jni::DecodeArtMethod(method_id);
//   return art_method;
// }

import Java from "frida-java-bridge";

export class JNI {
  handle: NativePointer;
  findClass: NativeFunction<
    NativePointer,
    [handle: NativePointer, className: NativePointer]
  >;
  getMethodID: NativeFunction<
    NativePointer,
    [
      handle: NativePointer,
      klass: NativePointer,
      methodName: NativePointer,
      signature: NativePointer,
    ]
  >;

  constructor() {
    const jniEnvPtr = Java.vm.getEnv().handle.readPointer();
    this.handle = jniEnvPtr;
    this.findClass = new NativeFunction(
      getJNIFunctionAddress(this.handle, "FindClass"),
      "pointer",
      ["pointer", "pointer"],
    );
    this.getMethodID = new NativeFunction(
      getJNIFunctionAddress(this.handle, "GetMethodID"),
      "pointer",
      ["pointer", "pointer", "pointer", "pointer"],
    );
  }

  getArtMethod(
    className: string,
    methodName: string,
    signature: string,
  ): NativePointer {
    const classNamePtr = Memory.allocAnsiString(className);

    const methodNamePtr = Memory.allocUtf8String(methodName);
    const signaturePtr = Memory.allocUtf8String(signature);

    // const JNIEnv = Java.vm.getEnv()
    // const klassPtr = JNIEnv.findClass(classNamePtr)
    // const methodIdPtr = JNIEnv.getMethodID(klassPtr, methodNamePtr, signaturePtr)
    const klassPtr = this.findClass(this.handle, classNamePtr);
    const methodIdPtr = this.getMethodID(
      this.handle,
      klassPtr,
      methodNamePtr,
      signaturePtr,
    );

    // This may be enough?
    return methodIdPtr;
  }
}

// export function getArtMethod(className: string, methodName: string, signature: string): NativePointer {
//   const classNamePtr = Memory.allocUtf8String(className)
//   const methodNamePtr = Memory.allocUtf8String(methodName)
//   const signaturePtr = Memory.allocUtf8String(signature)

//   const JNIEnv = Java.vm.getEnv()
//   const klassPtr = JNIEnv.findClass(classNamePtr)
//   const methodIdPtr = JNIEnv.getMethodID(klassPtr, methodNamePtr, signaturePtr)

//   // This may be enough?
//   return methodIdPtr
// }

// Borrowed from:
// https://github.com/Areizen/JNI-Frida-Hook/blob/master/utils/jni_struct.js
// class created from
// struct JNINativeInterface :
// https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#149

const jni_struct_array = [
  "reserved0",
  "reserved1",
  "reserved2",
  "reserved3",
  "GetVersion",
  "DefineClass",
  "FindClass",
  "FromReflectedMethod",
  "FromReflectedField",
  "ToReflectedMethod",
  "GetSuperclass",
  "IsAssignableFrom",
  "ToReflectedField",
  "Throw",
  "ThrowNew",
  "ExceptionOccurred",
  "ExceptionDescribe",
  "ExceptionClear",
  "FatalError",
  "PushLocalFrame",
  "PopLocalFrame",
  "NewGlobalRef",
  "DeleteGlobalRef",
  "DeleteLocalRef",
  "IsSameObject",
  "NewLocalRef",
  "EnsureLocalCapacity",
  "AllocObject",
  "NewObject",
  "NewObjectV",
  "NewObjectA",
  "GetObjectClass",
  "IsInstanceOf",
  "GetMethodID",
  "CallObjectMethod",
  "CallObjectMethodV",
  "CallObjectMethodA",
  "CallBooleanMethod",
  "CallBooleanMethodV",
  "CallBooleanMethodA",
  "CallByteMethod",
  "CallByteMethodV",
  "CallByteMethodA",
  "CallCharMethod",
  "CallCharMethodV",
  "CallCharMethodA",
  "CallShortMethod",
  "CallShortMethodV",
  "CallShortMethodA",
  "CallIntMethod",
  "CallIntMethodV",
  "CallIntMethodA",
  "CallLongMethod",
  "CallLongMethodV",
  "CallLongMethodA",
  "CallFloatMethod",
  "CallFloatMethodV",
  "CallFloatMethodA",
  "CallDoubleMethod",
  "CallDoubleMethodV",
  "CallDoubleMethodA",
  "CallVoidMethod",
  "CallVoidMethodV",
  "CallVoidMethodA",
  "CallNonvirtualObjectMethod",
  "CallNonvirtualObjectMethodV",
  "CallNonvirtualObjectMethodA",
  "CallNonvirtualBooleanMethod",
  "CallNonvirtualBooleanMethodV",
  "CallNonvirtualBooleanMethodA",
  "CallNonvirtualByteMethod",
  "CallNonvirtualByteMethodV",
  "CallNonvirtualByteMethodA",
  "CallNonvirtualCharMethod",
  "CallNonvirtualCharMethodV",
  "CallNonvirtualCharMethodA",
  "CallNonvirtualShortMethod",
  "CallNonvirtualShortMethodV",
  "CallNonvirtualShortMethodA",
  "CallNonvirtualIntMethod",
  "CallNonvirtualIntMethodV",
  "CallNonvirtualIntMethodA",
  "CallNonvirtualLongMethod",
  "CallNonvirtualLongMethodV",
  "CallNonvirtualLongMethodA",
  "CallNonvirtualFloatMethod",
  "CallNonvirtualFloatMethodV",
  "CallNonvirtualFloatMethodA",
  "CallNonvirtualDoubleMethod",
  "CallNonvirtualDoubleMethodV",
  "CallNonvirtualDoubleMethodA",
  "CallNonvirtualVoidMethod",
  "CallNonvirtualVoidMethodV",
  "CallNonvirtualVoidMethodA",
  "GetFieldID",
  "GetObjectField",
  "GetBooleanField",
  "GetByteField",
  "GetCharField",
  "GetShortField",
  "GetIntField",
  "GetLongField",
  "GetFloatField",
  "GetDoubleField",
  "SetObjectField",
  "SetBooleanField",
  "SetByteField",
  "SetCharField",
  "SetShortField",
  "SetIntField",
  "SetLongField",
  "SetFloatField",
  "SetDoubleField",
  "GetStaticMethodID",
  "CallStaticObjectMethod",
  "CallStaticObjectMethodV",
  "CallStaticObjectMethodA",
  "CallStaticBooleanMethod",
  "CallStaticBooleanMethodV",
  "CallStaticBooleanMethodA",
  "CallStaticByteMethod",
  "CallStaticByteMethodV",
  "CallStaticByteMethodA",
  "CallStaticCharMethod",
  "CallStaticCharMethodV",
  "CallStaticCharMethodA",
  "CallStaticShortMethod",
  "CallStaticShortMethodV",
  "CallStaticShortMethodA",
  "CallStaticIntMethod",
  "CallStaticIntMethodV",
  "CallStaticIntMethodA",
  "CallStaticLongMethod",
  "CallStaticLongMethodV",
  "CallStaticLongMethodA",
  "CallStaticFloatMethod",
  "CallStaticFloatMethodV",
  "CallStaticFloatMethodA",
  "CallStaticDoubleMethod",
  "CallStaticDoubleMethodV",
  "CallStaticDoubleMethodA",
  "CallStaticVoidMethod",
  "CallStaticVoidMethodV",
  "CallStaticVoidMethodA",
  "GetStaticFieldID",
  "GetStaticObjectField",
  "GetStaticBooleanField",
  "GetStaticByteField",
  "GetStaticCharField",
  "GetStaticShortField",
  "GetStaticIntField",
  "GetStaticLongField",
  "GetStaticFloatField",
  "GetStaticDoubleField",
  "SetStaticObjectField",
  "SetStaticBooleanField",
  "SetStaticByteField",
  "SetStaticCharField",
  "SetStaticShortField",
  "SetStaticIntField",
  "SetStaticLongField",
  "SetStaticFloatField",
  "SetStaticDoubleField",
  "NewString",
  "GetStringLength",
  "GetStringChars",
  "ReleaseStringChars",
  "NewStringUTF",
  "GetStringUTFLength",
  "GetStringUTFChars",
  "ReleaseStringUTFChars",
  "GetArrayLength",
  "NewObjectArray",
  "GetObjectArrayElement",
  "SetObjectArrayElement",
  "NewBooleanArray",
  "NewByteArray",
  "NewCharArray",
  "NewShortArray",
  "NewIntArray",
  "NewLongArray",
  "NewFloatArray",
  "NewDoubleArray",
  "GetBooleanArrayElements",
  "GetByteArrayElements",
  "GetCharArrayElements",
  "GetShortArrayElements",
  "GetIntArrayElements",
  "GetLongArrayElements",
  "GetFloatArrayElements",
  "GetDoubleArrayElements",
  "ReleaseBooleanArrayElements",
  "ReleaseByteArrayElements",
  "ReleaseCharArrayElements",
  "ReleaseShortArrayElements",
  "ReleaseIntArrayElements",
  "ReleaseLongArrayElements",
  "ReleaseFloatArrayElements",
  "ReleaseDoubleArrayElements",
  "GetBooleanArrayRegion",
  "GetByteArrayRegion",
  "GetCharArrayRegion",
  "GetShortArrayRegion",
  "GetIntArrayRegion",
  "GetLongArrayRegion",
  "GetFloatArrayRegion",
  "GetDoubleArrayRegion",
  "SetBooleanArrayRegion",
  "SetByteArrayRegion",
  "SetCharArrayRegion",
  "SetShortArrayRegion",
  "SetIntArrayRegion",
  "SetLongArrayRegion",
  "SetFloatArrayRegion",
  "SetDoubleArrayRegion",
  "RegisterNatives",
  "UnregisterNatives",
  "MonitorEnter",
  "MonitorExit",
  "GetJavaVM",
  "GetStringRegion",
  "GetStringUTFRegion",
  "GetPrimitiveArrayCritical",
  "ReleasePrimitiveArrayCritical",
  "GetStringCritical",
  "ReleaseStringCritical",
  "NewWeakGlobalRef",
  "DeleteWeakGlobalRef",
  "ExceptionCheck",
  "NewDirectByteBuffer",
  "GetDirectBufferAddress",
  "GetDirectBufferCapacity",
  "GetObjectRefType",
];

/**
 * Calculate the given funcName address from the JNIEnv pointer
 */
function getJNIFunctionAddress(
  jnienv_addr: NativePointer,
  func_name: string,
): NativePointer {
  const offset = jni_struct_array.indexOf(func_name) * Process.pointerSize;
  console.log(`offset : 0x${offset.toString(16)}`);
  return jnienv_addr.add(offset).readPointer();
}
