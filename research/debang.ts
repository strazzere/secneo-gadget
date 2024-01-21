import * as fs from 'fs';
import * as process from 'process';

function* findAll(data: Buffer, sub: Buffer): Generator<number, void, unknown> {
  let start = 0;
  while (true) {
    start = data.indexOf(sub, start);
    if (start === -1) return;
    yield start;
    start += sub.length;
  }
}

function nuke(fileName: string) {
  const data = fs.readFileSync(fileName);
  const sub = Buffer.from('DexHelper\0c_l_e__check1234567_', 'binary');
  const found = [...findAll(data, sub)];

  if (found.length !== 1) {
    console.log(`Expected to find exactly one occurrence of bangcle check, found ${found.length}`);
    return;
  }

  const replacedData = Buffer.from(data.toString('binary').replace('DexHelper\0c_l_e__check1234567_', '__b_a_n_g_c_l_e__check1234567_'), 'binary');
  fs.writeFileSync(`${fileName}-fixed`, replacedData);
  console.log(`Fixed ${fileName} and output as ${fileName}-fixed`);
}

nuke(process.argv[2]);
