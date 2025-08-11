# SecNeo Gadget

Gadget(s) for debugging, dumping and dissecting `secneo` protected applications via `typescript`.

*WARNING* : This is a relatively old and outdated approach to unpacking secneo. Essentially everything has changed after multiple articles posted methods to defeat the (now) older protections. This is open sourced now as it is not working out of the box, however it hopefully helps people with general frida functionality. _Do not open an issue asking why this doesn't work out of the box, because, I'm telling you right now, it doesn't_ - however there are lots of (hopefully) interesting usage patterns for people to reuse.

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

### Actually dumping the files

You'll need to enable the `dumpDexFiles()` call in `agent/secneo.ts` first, this will allow you to dump the `classes.dex` files on the fly. Pull these from the device `/data/data/dji.go.v5` (or a different package name if needed) - then find which classes need to be force loaded;

```sh
grep -r "nop" -A 3 out | grep "const" | grep -v 'x0, 0x0' | grep 'v0, 0x' | cut -d'.' -f1 | cut -d'/' -f3- | sort | uniq
```

The above may need to be adjusted a bit, however it should generally speaking work after you have run `baksmali` on all the dumped files. It works by trying to find methods that have the characteristic `nop const` pattern;

```smali
# virtual methods
.method public onFailure(Ljava/lang/Throwable;ILjava/lang/String;)V
    .registers 6

    :catch_0
    nop

    const v0, 0x1467acbd
```

Then sort and unique the file/classnames for usage in the agent. Take this list and replace the list in the `getNeededClasses()` - these will be forced loaded into the `ClassLoader` which should allow us to catch the decrypted methods.

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

## License

    Copyright (c) 2020-2025 Red Naga - Tim 'diff' Strazzere

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
