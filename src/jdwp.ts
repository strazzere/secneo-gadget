import net from 'net';
import { exec } from 'child_process';

const jdwpPort = 8200;
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function forwardJdwpPort(pid: number) {
  return new Promise((resolve, reject) => {
    exec(`adb forward tcp:${jdwpPort} jdwp:${pid}`, (error, stdout, stderr) => {
      if (error) {
        console.log(`error: ${error.message}`);
        reject(error);
        return;
      }
      if (stderr) {
        console.log(`stderr: ${stderr}`);
        return;
      }
      console.log(`stdout: ${stdout}`);
      resolve(true);
    });
  });
}

export async function triggerJdbConnect() {
  const jdb = net.connect({ host: 'localhost', port: jdwpPort });

  // jdb.on('data', (data: Buffer) => {
  //   console.log(`data <= ${data.toString('hex')}`);
  // });

  jdb.write(Buffer.from('4a4457502d48616e647368616b65', 'hex'));
  await delay(100);
  jdb.write(Buffer.from('0000000b00000001000107', 'hex'));
  await delay(100);
  jdb.write(Buffer.from('0000001100000003000f01080000000000', 'hex'));
  await delay(100);
  jdb.write(Buffer.from('0000001100000005000f01090000000000', 'hex'));
  await delay(100);
}
