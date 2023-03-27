import { log } from './logger';

export function getPackageName() {
  const pid = Process.id;

  // @ts-ignore
  const cmdline = new File(`/proc/${pid}/cmdline`, 'rb');

  // @ts-ignore
  let packageName = cmdline.readLine();
  log(`packageName: ${packageName}`)

  // @ts-ignore
  cmdline.close();

  if (packageName.includes(':')) {
    packageName = packageName.split(':').at(0);
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
      // @ts-ignore
      const out = new File(fileName, 'wb');
      // @ts-ignore
      out.write(dex);
      // @ts-ignore
      out.close();
    }
  } catch (e) {
    console.log(`[!] ${e}`);
  }
}
