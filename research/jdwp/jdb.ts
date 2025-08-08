import net from "node:net";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Connect to an exposed jdwp port and connect enough that it will think
// a normal debugger has attached.
async function connect() {
  const jdb = net.connect({ host: "localhost", port: 8200 });

  jdb.on("data", (data: Buffer) => {
    console.log(`data <= ${data.toString("hex")}`);
  });

  jdb.write(Buffer.from("4a4457502d48616e647368616b65", "hex"));
  await delay(100);
  jdb.write(Buffer.from("0000000b00000001000107", "hex"));
  await delay(100);
  jdb.write(Buffer.from("0000001100000003000f01080000000000", "hex"));
  await delay(100);
  jdb.write(Buffer.from("0000001100000005000f01090000000000", "hex"));
  await delay(100);
}

connect();
