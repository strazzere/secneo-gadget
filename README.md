# SecNeo Gadget

Gadget(s) for debugging, dumping and dissecting secneo protected applications

## Usage

In theory, if this is a stable release and all prerequisites are installed, just run;

```sh
$ npm start
```

### Setup

Script expects the correct version (that matches the node dependencies) of `frida` to be pushed to
`/data/local/tmp/frida-server`. Alternatively, just have the server already running on the device.
The target application (`dji.go.v5`) should also be installed. Then install all npm dependencies via
`npm install . -ci`.

## Agent Only usage

### How to compile & load for debugging

```sh
$ npm install -ci
$ npm run build
$ npm run spawn
```

The above works well when just debugging and utilizing the agent, if things are hooked enought to "out run" the anti-debug measures.


### Continuous building while developing

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
