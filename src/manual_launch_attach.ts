//
//
// This is deprecated code, the original approach was using a modified apk that
// enforced debuggability and then manually forced it to wait for a debugger to
// attach. However, since then I've been able to just inject into a an unmodified
// apk.
//
// This code is mostly for reference and incase we need to fall back in the future
// towards this.
//
//

import { exec } from "node:child_process";

import fs from "node:fs";
import net from "node:net";
import repl from "node:repl";
import frida, { type Application } from "frida";

// import { MessageType, ErrorMessage } from 'frida/dist/script';

const jdwpPort = 8200;
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runFridaServer() {
  return new Promise((resolve, reject) => {
    exec("adb shell ps -A | grep frida", (error, _stdout, _stderr) => {
      if (error) {
        exec(
          "adb shell su -c '/data/local/tmp/frida-server'",
          (error, _stdout, stderr) => {
            if (error) {
              reject(error);
              return;
            }
            if (stderr) {
              return;
            }
            resolve(true);
          },
        );
        // reject(error);
        return;
      }
      console.log(`Frida is already running, won't start it...`);
      resolve(true);
    });
  });
}

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
  const jdb = net.connect({ host: "localhost", port: jdwpPort });

  jdb.write(Buffer.from("4a4457502d48616e647368616b65", "hex"));
  await delay(100);
  jdb.write(Buffer.from("0000000b00000001000107", "hex"));
  await delay(100);
  jdb.write(Buffer.from("0000001100000003000f01080000000000", "hex"));
  await delay(100);
  jdb.write(Buffer.from("0000001100000005000f01090000000000", "hex"));
  await delay(100);
}

const agentScript = fs.readFileSync("./build/_agent.js", "utf8");

const targetIdentifier = "dji.go.v5";

type decryptedData = {
  address: number;
  comment: string;
};

const decrypted: decryptedData[] = [];

function dumpDecrypted() {
  fs.writeFileSync("comments.json", JSON.stringify(decrypted));
}

async function launchtarget() {
  await delay(1000);
  const device = await frida.getUsbDevice();

  if (!device) {
    throw new Error(
      "Expected to find a usb device attached, unable to continue",
    );
  }

  const matchingTargets: Application[] = (
    await device.enumerateApplications()
  ).filter((app) => app.identifier === targetIdentifier);

  if (!matchingTargets || matchingTargets.length <= 0) {
    throw new Error(
      `Expected to find a target matching identifier of ${targetIdentifier}`,
    );
  }
  const target = matchingTargets.at(0);

  let pid = target?.pid;

  if (!pid || pid <= 0) {
    pid = await device.spawn(targetIdentifier);
  }

  console.log("running device.attach");
  const session = await device.attach(pid);
  console.log("creating script");
  const script = await session.createScript(agentScript);
  script.message.connect((message) => {
    // switch (message.type) {
    // case MessageType.Send:
    //   if (message?.payload?.type === 'decrypt') {
    //     decrypted.push(message?.payload?.decrypted);
    //   }
    //   break;
    // case MessageType.Error:
    //   console.log(`Error received from script: ${(message as ErrorMessage).stack}`);
    //   break;
    // default:
    console.log(`Unknown message type received : ${message}`);
    // }
  });

  console.log("loading script");
  await script.load();

  console.log("running forwardJdwpPort");
  await forwardJdwpPort(pid);
  console.log("running triggerJdbConnect");
  await triggerJdbConnect();
}

// this is a dangling promise because it shouldn't return for us
console.log("Running frida-server");
runFridaServer();

launchtarget().then(() => {
  console.log("Done launching target");

  repl.start("secneo-gadget >").context.dump = dumpDecrypted;
});
