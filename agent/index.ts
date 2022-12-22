import { log } from './logger';
import { Stack } from './stack';
import { hookCallFunction } from './linker';

const debug = false;

const stack = new Stack();
const getStack = () => {
  log(stack.java());
};

hookCallFunction('libDexHelper.so', (pointer) => {
  log(`Hit function call back for hookCallFunction and value is ${pointer}`);
  getStack();
});

console.log(`(Re?)loaded`);
