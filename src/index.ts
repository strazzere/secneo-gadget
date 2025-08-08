import { exec } from "node:child_process";
import fs from "node:fs";
import repl from "node:repl";
import type { Script } from "frida";
import frida, { type Application } from "frida";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const agentScript = fs.readFileSync("./build/_agent.js", "utf8");

const targetIdentifier = "dji.go.v5";

// type decryptedData = {
//   address: number;
//   comment: string;
// };

// const decrypted: decryptedData[] = [];

// function dumpDecrypted() {
//   fs.writeFileSync(`comments.json`, JSON.stringify(decrypted));
// }

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
        return;
      }
      console.log("Frida is already running, won't start it...");
      resolve(true);
    });
  });
}

let script: Script | null;

function stop() {
  if (script !== null) {
    script.unload();
    script = null;
  }
}

async function main() {
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
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
  if (pid) {
    console.log("Found pid already running, killing it");
    await device.kill(pid);
  }

  console.log("Launching target application, then attaching.");
  pid = await device.spawn(targetIdentifier);

  console.log("running device.attach");
  const session = await device.attach(pid);

  session.detached.connect((reason) => {
    console.log(` > detached : ${reason}`);
  });

  console.log("creating script");
  script = await session.createScript(agentScript);
  script.message.connect((message) => {
    console.log(`Unknown message type received : ${JSON.stringify(message)}`);
    console.log(message);
  });

  console.log("loading script");
  await script.load();
  await session.resume();

  const replServer = repl.start("secneo-gadget > ");
  replServer.context.device = device;
  replServer.context.script = script;
  replServer.context.session = session;
  replServer.context.target = target;
}

// this is a dangling promise because it shouldn't return for us
console.log("Running frida-server if needed");
runFridaServer();

main().catch((e) => {
  console.log(e);
});
