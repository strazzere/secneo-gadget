import { log } from './logger';

export function writeDexToFile(address: NativePointer) {
  try {
    const dex_size = address.add(0x20).readU32();
    const file_name =
      '/data/data/dji.go.v5/unpacked_' + address + '_' + dex_size.toString(0x10) + '.dex';
    log('[*] Writing dex to', file_name);
    const dex = address.readByteArray(dex_size);
    if (dex) {
      const out = new File(file_name, 'wb');
      out.write(dex);
      out.close();
    }
  } catch (e) {
    console.log('[!] ', e);
  }
}
