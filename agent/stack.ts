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
        stackString = stackString.concat(`${index} => ${stackLayer.toString()}`);
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
}
