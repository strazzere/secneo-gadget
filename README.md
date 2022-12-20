# SecNeo Gadget

Gadget(s) for debugging, dumping and dissecting secneo protected applications

## How to inject

Rebuild APK and ensure it loads the [frida gadget](https://frida.re/docs/gadget/#:~:text=Frida's%20Gadget%20is%20a%20shared,using%20a%20tool%20like%20insert_dylib), config and script builts from `npm build`.

### How to compile & load for debugging

```sh
$ npm install
$ frida -U -p `frida-ps -U | grep 'RS Fly' | cut -d' ' -f1 ` --no-pause -l _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
