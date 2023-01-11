/**
 * Helper class for getting stack traces and backtraces.
 */
export class Stack {
  private threadObj: Java.Wrapper<object>;

  constructor() {
    if (!Java.available) {
      throw new Error(`Unable to initialize a Java stacktrace object when Java is unavailable`);
    }
    Java.perform(() => {
      const ThreadDef = Java.use('java.lang.Thread');
      this.threadObj = ThreadDef.$new();
    });
  }

  /**
   * @returns {string} a java stack trace of where this was called
   */
  java(): string {
    if (!this.threadObj) {
      throw new Error(`No java stack available as no thread object available`);
    }
    let stackString = '';
    this.threadObj
      .currentThread()
      .getStackTrace()
      .map((stackLayer: string, index: number) => {
        // Ignore our own creations on the stack (getStackStrace/getThreadStackTrace)
        if (index > 1) {
          stackString = stackString.concat(`${index - 1} => ${stackLayer.toString()}\n`);
        }
      });

    return stackString;
  }

  /**
   * @param context in which to get a native backtrace
   * @returns string of backtrace
   */
  static native(context: CpuContext) {
    return (
      Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n'
    );
  }

  /**
   * For some reason, DebugSymbol.fromAddress doesn't always work,
   * nor does Process.getModuleFromAddress, so utilize enumerating the
   * addresses manually to figure out what the module is and the local
   * offset inside it.
   * @param pointer
   * @returns string of relevant data
   */
  static getModuleInfo(pointer: NativePointer) {
    const debugSymbol = DebugSymbol.fromAddress(pointer);
    if (debugSymbol.moduleName) {
      // Add local offset?
      return debugSymbol.toString();
    }

    // When hooking we might get something interesting like the following;
    //  [
    //    {
    //      "base": "0x76fa7000",    <==== [anon:dalvik-free list large object space]
    //      "protection": "rw-",           we don't actually care about this
    //      "size": 536870912
    //    },
    //    {
    //      "base": "0x771e939000", <==== this isn't the actual base, we need to refind that
    //      "file": {
    //        "offset": 663552,
    //         "path": "/apex/com.android.runtime/lib64/bionic/libc.so",
    //         "size": 0
    //      },
    //     "protection": "rwx",
    //     "size": 4096
    //   }
    // ]
    const builtSymbol = {
      base: ptr(0x0),
      moduleName: '',
      path: '',
      size: 0,
    };
    let ranges = Process.enumerateRanges('').filter(
      (range) => range.base <= pointer && range.base.add(range.size) >= pointer,
    );
    ranges.forEach((range) => {
      if (range.file) {
        builtSymbol.path = range.file.path;
        const moduleNameChunks = range.file.path.split('/');
        builtSymbol.moduleName = moduleNameChunks[moduleNameChunks.length - 1];

        builtSymbol.base = range.base.sub(range.file.offset);
      }
    });

    ranges = Process.enumerateRanges('').filter(
      (range) => range.base <= builtSymbol.base && range.base.add(range.size) >= builtSymbol.base,
    );
    ranges.forEach((range) => {
      if (builtSymbol.base === ptr(0x0) || builtSymbol.base < range.base) {
        builtSymbol.base = range.base;
      }
      builtSymbol.size += range.size;
    });

    return `${builtSymbol.base} ${builtSymbol.moduleName}:${pointer.sub(builtSymbol.base)}`;
  }
}
