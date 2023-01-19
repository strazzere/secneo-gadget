import fs from 'fs';
import cliProgress from 'cli-progress';
import { findSourceMap } from 'module';

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
  buffer.copy(dataSegment, 0, dataOffset, dataSize);

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
  file.dataSegment.buffer.copy(
    wholeFile,
    file.dataSegment.offset,
    0,
    file.dataSegment.buffer.length,
  );

  const newFileName = `${file.fileName}.fixed`;
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

  const deduped: string[] = [];
  bytecodeData.forEach((element: any) => {
    if (element?.data && !deduped.includes(element.data)) {
      deduped.push(element.data);
    }
  });
  const dupesRemoved = bytecodeData.length - deduped.length;
  console.log(
    ` [+] Dex methods to recover: ${deduped.length} ${
      dupesRemoved > 0
        ? `(${dupesRemoved} duplicate${dupesRemoved > 1 ? 's removed' : ' removed'})`
        : ''
    }`,
  );

  const dexFiles = fs
    .readdirSync(directory)
    .filter((file) => file.endsWith('.dex'))
    .map((file) => readDexFile(`${directory}/${file}`));

  console.log(` [+] Read in ${dexFiles.length} dex files`);

  const progress = new cliProgress.SingleBar({}, cliProgress.Presets.shades_classic);

  // start the progress bar with a total value of 200 and start value of 0
  progress.start(deduped.length, 0);
  console.time(' [+] Function Matching');
  let matched: string[] = [];
  let unmatched: string[] = [];
  deduped.forEach((codeItem) => {
    const codeBuffer = Buffer.from(codeItem, 'hex');
    const codeNeedle = codeBuffer.slice(0, 11);
    const written = dexFiles.some((dexFile) => {
      if (dexFile.dataSegment.buffer.includes(codeNeedle)) {
        dexFile.dataSegment.hits++;
        dexFile.dataSegment.buffer.write(
          codeBuffer.toString(),
          dexFile.dataSegment.buffer.indexOf(codeNeedle),
        );
        return true;
      }
      return false;
    });
    if (written) {
      progress.increment();
      matched.push(codeItem);
    } else {
      unmatched.push(codeItem);
    }
  });

  progress.stop();
  console.timeEnd(' [+] Function Matching');

  console.log(` [+] Matched : ${matched.length}`);
  fs.writeFileSync(`${directory}/matched.out`, matched.join('\n'));
  console.log(` [-] Unmatched : ${unmatched.length}`);
  fs.writeFileSync(`${directory}/unmatched.out`, unmatched.join('\n'));

  dexFiles.forEach((file) => {
    const writtenFile = writeDexFile(file);
    console.log(` [+] Wrote out fixed dex file ${writtenFile}`);
  });
}

main().catch((e) => {
  console.log(e);
});
