import fs from "node:fs";
import cliProgress from "cli-progress";

// 00000000  64 65 78 0a 30 33 37 00  d9 46 30 17 6c 32 ed 82  |dex.037..F0.l2..|
// 00000010  5d 65 ec 24 8b fb fe 96  82 08 8d 77 21 76 31 06  |]e.$.......w!v1.|
// 00000020  d4 55 87 00 70 00 00 00  78 56 34 12 00 00 00 00  |.U..p...xV4.....|
// 00000030  00 00 00 00 9c 9d 15 00  f6 9c 00 00 70 00 00 00  |............p...|
// 00000040  74 21 00 00 48 74 02 00  03 30 00 00 18 fa 02 00  |t!..Ht...0......|
// 00000050  29 d8 00 00 3c 3a 05 00  7d ca 00 00 84 fb 0b 00  |)...<:..}.......|
// 00000060  70 1a 00 00 6c 4f 12 00  38 b8 71 00 9c 9d 15 00  |p...lO..8.q.....|

function isDex(buffer: Buffer): boolean {
  if (
    Buffer.compare(buffer.subarray(0, 8), Buffer.from("dex\n037\x00")) !== 0
  ) {
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
      `Buffer provided does not appear to be a DEX file : [${buffer.subarray(0, 8).toString("hex")}]`,
    );
  }

  const dataSize = buffer.readUintLE(0x68, 0x4);
  const dataOffset = buffer.readUintLE(0x6c, 0x4);

  if (dataOffset + dataSize > buffer.length) {
    throw new Error(
      "Buffer provided does not appear to be a valid DEX file, data segment would extend past end of buffer",
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
  console.log("[*] SecNeo Stolen Bytecode Rebuilder\n");

  const directory = process.argv[2];
  if (!directory) {
    console.error("Usage: combine <directory>");
    process.exit(1);
  }
  const bytecodeData = JSON.parse(
    fs.readFileSync(`${directory}/data.json`, "utf-8"),
  );

  if (!bytecodeData || bytecodeData.length <= 0) {
    throw new Error("Unable to find any bytecode data to replace");
  }

  const needleSet = new Set<string>();
  const entries: { needle: string; data: string }[] = [];

  console.time(" [!] Removed duplicates and unneeded functions");
  for (let i = 0; i < bytecodeData.length; i++) {
    if (
      bytecodeData[i]?.needle &&
      bytecodeData[i]?.data &&
      // We don't need to bother searching for a needle that is going to be replaced by the same thing
      bytecodeData[i]?.needle !== bytecodeData[i]?.data &&
      !needleSet.has(bytecodeData[i].needle)
    ) {
      entries.push({
        needle: bytecodeData[i].needle,
        data: bytecodeData[i].data,
      });
      needleSet.add(bytecodeData[i].needle);
    }
  }
  console.timeEnd(" [!] Removed duplicates and unneeded functions");
  const itemsRemoved = bytecodeData.length - entries.length;
  console.log(
    ` [+] Dex methods to recover: ${entries.length} ${
      itemsRemoved > 0
        ? `(${itemsRemoved} unneeded method${itemsRemoved > 1 ? "s removed" : " removed"})`
        : ""
    }`,
  );

  fs.writeFileSync("./deduped.json", JSON.stringify(entries));

  // Would be more interesting if we could dynamically type that these don't have issues
  // but for the time being, I don't care much to solve that and we can just hardcode them
  // from knowledge derived from past runs
  //
  // Specific to 1.8 dump
  //    `unpacked_0xb40000703970cfdc_1c2254.dex`,
  //    `unpacked_0xb40000703951ffdc_1ec37c.dex`,
  //    `unpacked_0xb400007039289fdc_295d44.dex`,
  //    `unpacked_0xb400007038e24fdc_4647a0.dex`,
  //    `unpacked_0xb400007038ba1fdc_282fc0.dex`,
  //

  // Specific to 1.9 dump
  // 'unpacked_0xb400006e97441ff0_45c21c.dex',
  // 'unpacked_0xb400006e9789eff0_33b3ac.dex',
  // 'unpacked_0xb400006e97bdaff0_2776d8.dex',
  // 'unpacked_0xb400006e97e52ff0_443c3c.dex',
  // 'unpacked_0xb400006e98296ff0_1a3918.dex',
  // 'unpacked_0xb400006e9843aff0_1e2148.dex',

  const dexToSkip: string[] = [];

  const dexFiles = fs
    .readdirSync(directory)
    .filter((file) => file.endsWith(".dex"))
    .filter((file) => !dexToSkip.includes(file))
    .map((file) => readDexFile(`${directory}/${file}`));

  console.log(` [+] Read in ${dexFiles.length} dex files`);

  const progress = new cliProgress.SingleBar(
    {},
    cliProgress.Presets.shades_classic,
  );

  // Pre-convert all hex strings to Buffers and build a prefix hash map
  // for single-pass scanning through each dex data segment
  const PREFIX_LEN = 4;
  const needleBuffers: Buffer[] = entries.map((e) =>
    Buffer.from(e.needle, "hex"),
  );
  const dataBuffers: Buffer[] = entries.map((e) => Buffer.from(e.data, "hex"));
  const prefixMap = new Map<number, number[]>();
  const shortNeedles: number[] = [];

  for (let i = 0; i < needleBuffers.length; i++) {
    if (needleBuffers[i].length < PREFIX_LEN) {
      shortNeedles.push(i);
      continue;
    }
    const prefix = needleBuffers[i].readUInt32LE(0);
    let bucket = prefixMap.get(prefix);
    if (!bucket) {
      bucket = [];
      prefixMap.set(prefix, bucket);
    }
    bucket.push(i);
  }

  const matchedFlags = new Uint8Array(entries.length);
  let remaining = entries.length;

  progress.start(entries.length, 0);
  console.time(" [+] Function Matching");

  for (let x = 0; x < dexFiles.length && remaining > 0; x++) {
    const buf = dexFiles[x].dataSegment.buffer;

    // Single-pass scan using prefix hash map
    for (
      let offset = 0;
      offset <= buf.length - PREFIX_LEN && remaining > 0;
      offset++
    ) {
      const prefix = buf.readUInt32LE(offset);
      const candidates = prefixMap.get(prefix);
      if (!candidates) continue;

      for (let c = 0; c < candidates.length; c++) {
        const idx = candidates[c];
        const needle = needleBuffers[idx];
        if (offset + needle.length > buf.length) continue;

        if (
          buf.compare(
            needle,
            0,
            needle.length,
            offset,
            offset + needle.length,
          ) === 0
        ) {
          dataBuffers[idx].copy(buf, offset);
          dexFiles[x].dataSegment.hits++;
          matchedFlags[idx] = 1;
          remaining--;
          progress.increment();
          // Remove matched entry from bucket
          candidates.splice(c, 1);
          if (candidates.length === 0) prefixMap.delete(prefix);
          break;
        }
      }
    }

    // Fallback for needles shorter than prefix length
    for (let s = 0; s < shortNeedles.length && remaining > 0; s++) {
      const idx = shortNeedles[s];
      if (matchedFlags[idx]) continue;
      const needle = needleBuffers[idx];
      const index = buf.indexOf(needle);
      if (index !== -1) {
        dataBuffers[idx].copy(buf, index);
        dexFiles[x].dataSegment.hits++;
        matchedFlags[idx] = 1;
        remaining--;
        progress.increment();
      }
    }
  }

  // Finalize progress for any unmatched entries
  progress.update(entries.length);
  progress.stop();
  console.timeEnd(" [+] Function Matching");

  const matched: string[] = [];
  const unmatched: string[] = [];
  for (let i = 0; i < entries.length; i++) {
    if (matchedFlags[i]) {
      matched.push(entries[i].data);
    } else {
      unmatched.push(entries[i].needle);
    }
  }

  console.log(` [+] Matched : ${matched.length}`);
  fs.writeFileSync(`${directory}/matched.out`, matched.join("\n"));
  console.log(` [-] Unmatched : ${unmatched.length}`);
  fs.writeFileSync(`${directory}/unmatched.out`, unmatched.join("\n"));

  for (const file of dexFiles) {
    const writtenFile = writeDexFile(file);
    console.log(
      ` [+] Wrote out fixed dex file ${writtenFile} which contained ${file.dataSegment.hits}`,
    );
  }
}

main().catch((e) => {
  console.log(e);
});
