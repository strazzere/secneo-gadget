//
// 1. Expose the jdwp port via adb
// 2. node jdwp-proxy.ts
// 3. jdb -attach localhost:8100
//
// This gives us the following output, which we likely
// can use to just cause the `Waiting for debugger` output to be knocked away
//
// $ node jdwp-proxy.js
// server => conneciton
// server => data(4a4457502d48616e647368616b65)
// server => data(0000000b00000001000107)
// server => data(0000001100000003000f01080000000000)
// server => data(0000001100000005000f01090000000000)
// server => data(0000002e00000007000f0108020000000205000000136a6176612e6c616e672e5468726f7761626c650100000001)
// server => data(0000000b00000009000101)
// server => data(0000000b0000000b000114)
// server => data(0000001c0000000d000f010402000000010800000000000021ba0001)
// server => data(000000100000000f000f020800000004)
// server => data(0000001100000011000f01060200000000)
// server => data(0000001100000013000f01070200000000)
// server => data(0000000b0000001500010d)
// server => data(0000000b0000001a000104)
// server => data(0000000b0000001c000109)
//
import net from 'net';

const proxy = net.connect({ host: 'localhost', port: 8200 });
const server = net.createServer((socket) => {
  socket.on('data', (data) => {
    console.log(`server => data(${data.toString('hex')})`);
    proxy.write(data);
  });
  proxy.on('data', (data) => {
    socket.write(data);
  });
});

server.on('connection', () => {
  console.log(`server => connection`);
});

server.listen(8100, 'localhost');
