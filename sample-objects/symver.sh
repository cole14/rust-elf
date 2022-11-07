#!/bin/bash
gcc -o symver.x86_64.so symver.c -Wl,--as-needed -shared -fPIC -Xlinker --hash-style=both -Wl,--version-script=symver.ver
