#!/bin/bash
gcc -o hello.so hello.c -Wl,--as-needed -shared -fPIC -Xlinker --hash-style=both -Wl,--version-script=hello.ver
