# Connecting to a secneo specific application

Annoyingly, Android has become a bit unreliable on allowing the root user to force an application into a waiting for debugger state. So to ensure this happens, we need to decode the resources (via `apktool` or something) and mark the application as `android:debuggable="true"`.

After this is done, resign the apk and install. Then mark the application as debuggable and to wait as a persisted value. This is done by getting root and doing the following;
```sh
$ su
# am set-debug-app -w --persistent dji.go.v5
```

This in theory can work on some devices without the application being marked as debuggable, however it isn't always respected depending on the version of ART running.

Now the application will wait at the expected `Waiting for debugger...` dialog. So at this point we can attach and inject our `frida` (or whatever) code. To trigger the application to continue we just need to attach `jdb` e.g. --

```sh
$ 
```