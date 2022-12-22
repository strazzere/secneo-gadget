import frida, { Application } from 'frida';
import { forwardJdwpPort, triggerJdbConnect } from './jdwp';

import fs from 'fs';

const agentScript = fs.readFileSync('./build/_agent.js', 'utf8');

const targetIdentifier = 'dji.go.v5';

async function launchtarget() {
  const device = await frida.getUsbDevice();

  if (!device) {
    throw new Error(`Expected to find a usb device attached, unable to continue`);
  }

  const matchingTargets: Application[] = (await device.enumerateApplications()).filter(
    (app) => app.identifier === targetIdentifier,
  );

  if (!matchingTargets || matchingTargets.length <= 0) {
    throw new Error(`Expected to find a target matching identifier of ${targetIdentifier}`);
  }
  const target = matchingTargets.at(0);

  let pid = target?.pid;

  if (!pid || pid <= 0) {
    pid = await device.spawn(targetIdentifier);
  }

  console.log(`running device.attach`);
  const session = await device.attach(pid);
  console.log(`creating script`);
  const script = await session.createScript(agentScript);
  console.log(`loading script`);
  await script.load();

  console.log(`running forwardJdwpPort`);
  await forwardJdwpPort(pid);
  console.log(`running triggerJdbConnect`);
  await triggerJdbConnect();
}

launchtarget().then(() => {
  console.log('Done launching target');
});
