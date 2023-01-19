import fs from 'fs';
import cliProgress from 'cli-progress';

// 00000000  64 65 78 0a 30 33 37 00  d9 46 30 17 6c 32 ed 82  |dex.037..F0.l2..|
// 00000010  5d 65 ec 24 8b fb fe 96  82 08 8d 77 21 76 31 06  |]e.$.......w!v1.|
// 00000020  d4 55 87 00 70 00 00 00  78 56 34 12 00 00 00 00  |.U..p...xV4.....|
// 00000030  00 00 00 00 9c 9d 15 00  f6 9c 00 00 70 00 00 00  |............p...|
// 00000040  74 21 00 00 48 74 02 00  03 30 00 00 18 fa 02 00  |t!..Ht...0......|
// 00000050  29 d8 00 00 3c 3a 05 00  7d ca 00 00 84 fb 0b 00  |)...<:..}.......|
// 00000060  70 1a 00 00 6c 4f 12 00  38 b8 71 00 9c 9d 15 00  |p...lO..8.q.....|

function isDex(buffer: Buffer): boolean {
  if (Buffer.compare(buffer.slice(0, 8), Buffer.from('dex\n037\x00')) !== 0) {
    return false;
  }

  return true;
}

type File = {
  fileName: string;
  dataSegment: DataSegment;
};

type DataSegment = {
  offset: number;
  buffer: Buffer;
  hits: number;
};

function getDataSegment(buffer: Buffer): DataSegment {
  if (!isDex(buffer)) {
    throw new Error(
      `Buffer provided does not appear to be a DEX file : [${buffer.slice(0, 8).toString('hex')}]`,
    );
  }

  const dataSize = buffer.readUintLE(0x68, 0x4);
  const dataOffset = buffer.readUintLE(0x6c, 0x4);

  if (dataOffset + dataSize > buffer.length) {
    throw new Error(
      `Buffer provided does not appear to be a valid DEX file, data segment would extend past end of buffer`,
    );
  }

  const dataSegment = Buffer.allocUnsafe(dataSize);
  buffer.copy(dataSegment, 0, dataOffset, dataOffset + dataSize);

  return {
    offset: dataOffset,
    buffer: dataSegment,
    hits: 0,
  };
}

function readDexFile(file: string): File {
  return {
    fileName: file,
    dataSegment: getDataSegment(fs.readFileSync(file)),
  };
}

function writeDexFile(file: File): string {
  const wholeFile = fs.readFileSync(file.fileName);
  file.dataSegment.buffer.copy(wholeFile, file.dataSegment.offset);

  const newFileName = `${file.fileName}.fixed.dex`;
  fs.writeFileSync(newFileName, wholeFile);

  return newFileName;
}

async function main() {
  console.log(`[*] SecNeo Stolen Bytecode Rebuilder\n`);

  const directory = './dumped';
  const bytecodeData = JSON.parse(fs.readFileSync(`${directory}/data.json`, 'utf-8'));

  if (!bytecodeData && bytecodeData.length <= 0) {
    throw new Error(`Unable to find any bytecode data to replace`);
  }

  const decryptedCodes: string[] = [];
  const needles: string[] = [];

  console.time(` [!] Deduping`);
  for (let i = 0; i < bytecodeData.length; i++) {
    if (
      bytecodeData[i]?.needle &&
      bytecodeData[i]?.data &&
      !needles.includes(bytecodeData[i].needle)
    ) {
      decryptedCodes.push(bytecodeData[i].data);
      needles.push(bytecodeData[i].needle);
    }
  }
  console.timeEnd(` [!] Deduping`);
  const dupesRemoved = bytecodeData.length - decryptedCodes.length;
  console.log(
    ` [+] Dex methods to recover: ${decryptedCodes.length} ${
      dupesRemoved > 0
        ? `(${dupesRemoved} duplicate${dupesRemoved > 1 ? 's removed' : ' removed'})`
        : ''
    }`,
  );
  const saveDeduped = true;
  if (saveDeduped) {
    const deduped = [];
    for (let i = 0; i < decryptedCodes.length; i++) {
      deduped.push({ needle: needles[i], data: decryptedCodes[i] });
    }

    fs.writeFileSync(`./deduped.json`, JSON.stringify(deduped));
  }

  // Would be more interesting if we could dynamically type that these don't have issues
  // but for the time being, I don't care much to solve that and we can just hardcode them
  // from knowledge derived from past runs
  const dexToSkip = [
    `unpacked_0xb40000703970cfdc_1c2254.dex`,
    `unpacked_0xb40000703951ffdc_1ec37c.dex`,
    `unpacked_0xb400007039289fdc_295d44.dex`,
    `unpacked_0xb400007038e24fdc_4647a0.dex`,
    `unpacked_0xb400007038ba1fdc_282fc0.dex`,
  ];

  const dexFiles = fs
    .readdirSync(directory)
    .filter((file) => file.endsWith('.dex'))
    .filter((file) => !dexToSkip.includes(file))
    .map((file) => readDexFile(`${directory}/${file}`));

  console.log(` [+] Read in ${dexFiles.length} dex files`);

  const progress = new cliProgress.SingleBar({}, cliProgress.Presets.shades_classic);

  progress.start(decryptedCodes.length, 0);
  console.time(' [+] Function Matching');
  const matched: string[] = [];
  const unmatched: string[] = [];

  // This is actually faster over the long run than using a forEach
  for (let i = 0; i < decryptedCodes.length; i++) {
    const needle = Buffer.from(needles[i], 'hex');
    let written = false;
    for (let x = 0; x < dexFiles.length; x++) {
      const index = dexFiles[x].dataSegment.buffer.indexOf(needle);
      if (index !== -1) {
        const codeBuffer = Buffer.from(decryptedCodes[i], 'hex');
        dexFiles[x].dataSegment.hits++;
        codeBuffer.copy(dexFiles[x].dataSegment.buffer, index);
        written = true;
        break;
      }
    }

    if (written) {
      progress.increment();
      matched.push(decryptedCodes[i]);
    } else {
      unmatched.push(needles[i]);
    }
  }

  progress.stop();
  console.timeEnd(' [+] Function Matching');

  console.log(` [+] Matched : ${matched.length}`);
  fs.writeFileSync(`${directory}/matched.out`, matched.join('\n'));
  console.log(` [-] Unmatched : ${unmatched.length}`);
  fs.writeFileSync(`${directory}/unmatched.out`, unmatched.join('\n'));

  dexFiles.forEach((file) => {
    const writtenFile = writeDexFile(file);
    console.log(
      ` [+] Wrote out fixed dex file ${writtenFile} which contained ${file.dataSegment.hits}`,
    );
  });
}

main().catch((e) => {
  console.log(e);
});
