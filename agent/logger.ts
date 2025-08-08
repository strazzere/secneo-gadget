// biome-ignore lint/suspicious/noExplicitAny: allow any typing
export function log(message?: any, ...optionalParams: any[]): void {
  console.log(message, ...optionalParams);
}
