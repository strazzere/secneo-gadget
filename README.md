# SecNeo Gadget

Gadget(s) for debugging, dumping and dissecting secneo protected applications

## Usage

### How to inject

Rebuild APK and ensure it loads the [frida gadget](https://frida.re/docs/gadget/#:~:text=Frida's%20Gadget%20is%20a%20shared,using%20a%20tool%20like%20insert_dylib), config and script builts from `npm build`.

## Agent Only usage

### How to compile & load for debugging

```sh
$ npm install
$ npm run build
$ frida -U -f dji.go.v5 -l build/_agent.js
```

The above works well when just debugging and utilizing the agent, if things are hooked enought to "out run" the anti-debug measures.

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
