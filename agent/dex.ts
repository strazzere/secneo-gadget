import { log } from "./logger.js";

export function getPackageName(): string | undefined {
  const pid = Process.id;

  const cmdline = new File(`/proc/${pid}/cmdline`, "rb");

  let packageName: string | undefined = cmdline.readLine();
  log(`packageName: ${packageName}`);

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
      const out = new File(fileName, "wb");
      out.write(dex);
      out.close();
    }
  } catch (e) {
    console.log(`[!] ${e}`);
  }
}
