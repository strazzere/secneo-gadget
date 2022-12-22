import frida from 'frida';

const target = 'dji.v5.go';

async function launchtarget() {
  const device = await frida.getUsbDevice();

  if (!device) {
    throw new Error(`Expected to find a usb device attached, unable to continue`);
  }

  device.spawn('dji.go.v5', {});
}

launchtarget().then(() => {
  console.log('Done launching target');
});
