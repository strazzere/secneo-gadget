import { getPackageName } from './dex.js';
import { log } from './logger.js';

import { WriteStream, createWriteStream } from 'fs';
import { Buffer } from 'node:buffer';

export class NeedleMap {
  needles: number;
  fileName: string;
  outputStream: WriteStream | undefined;

  constructor() {
    this.fileName = `/data/data/${getPackageName()}/needleMap.json`;
    log(`Needle writer pointing to : ${this.fileName}`);
    this.needles = 0;

    this.outputStream = createWriteStream(this.fileName);
    this.outputStream.write('[\n\t');
  }

  isOpen(): boolean {
    return this.outputStream !== undefined;
  }

  close() {
    if (!this.outputStream) {
      throw new Error(`Outputstream already closed`);
    }
    log(`Closing needle writer after writing ${this.needles} to ${this.fileName}`);

    this.outputStream.write('\n]');

    // Close out the stream and set it to undefined so we don't mistakenly write more
    this.outputStream.end();
    this.outputStream = undefined;
  }

  writeNeedle(needleData: Uint8Array, data: Uint8Array) {
    if (!this.outputStream) {
      throw new Error(`Outputstream already closed`);
    }
    if (this.needles > 0) {
      this.outputStream.write(',\n\t');
    }
    this.needles++;

    const needleString = `{ "needle": "${Buffer.from(new Uint8Array(needleData)).toString(
      'hex',
    )}", "data" : "${Buffer.from(new Uint8Array(data)).toString('hex')}" }`;

    this.outputStream.write(needleString);
  }
}
