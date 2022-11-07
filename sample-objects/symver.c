
#include <string.h>

int use_memset(unsigned char *buf, size_t n) {
    memset(buf, 0, n);
}

int use_memset_v2(unsigned char *buf) {
    memset(buf, 0, 42);
}

__asm__(".symver use_memset, use_memset@HELLO_1.0");
__asm__(".symver use_memset_v2, use_memset_v2@HELLO_1.42");
