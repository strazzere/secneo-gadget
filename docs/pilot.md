# Debugging pilot

In an odd turn of events, pilot seems to be using a really old version of SecNeo that does less anti-debug work. It also annoyingly can cause the pid/package attachment to be wrong (frida bug?) so currently we get around this by just loading after we inject ourselves via the `%load './build/_agent.js'` command;

```sh
frida -U -f com.dji.industry.pilot
     ____
    / _  |   Frida 16.0.2 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 4 (id=98191FFAZ001NA)
Spawned `com.dji.industry.pilot`. Resuming main thread!                 
[Pixel 4::com.dji.industry.pilot ]->  %load './build/_agent.js' 
...
```