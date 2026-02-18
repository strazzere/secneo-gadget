import { log } from "./logger.js";

export function getPackageName(): string | undefined {
  const pid = Process.id;

  // @ts-expect-error
  const cmdline = new File(`/proc/${pid}/cmdline`, "rb");

  // @ts-expect-error
  let packageName: string | undefined = cmdline.readLine();
  log(`packageName: ${packageName}`);

  // @ts-expect-error
  cmdline.close();

  if (packageName?.includes(":")) {
    packageName = packageName.split(":").at(0);
  }

  return packageName;
}

export function writeDexToFile(address: NativePointer) {
  try {
    const dexSize = address.add(0x20).readU32();
    const fileName = `/data/data/${getPackageName()}/unpacked_${address}_${dexSize.toString(
      0x10,
    )}.dex`;
    log(`[*] Writing dex to ${fileName}`);
    const dex = address.readByteArray(dexSize);
    if (dex) {
      // @ts-expect-error
      const out = new File(fileName, "wb");
      // @ts-expect-error
      out.write(dex);
      // @ts-expect-error
      out.close();
    }
  } catch (e) {
    console.log(`[!] ${e}`);
  }
}
