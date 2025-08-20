#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    size_t cap = 1 << 16;
    uint8_t *buf = mmap(NULL, cap, PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 2; }

    size_t n = 0; uint8_t tmp[4096];
    for (;;) {
        ssize_t r = read(0, tmp, sizeof tmp);
        if (r < 0) { perror("read"); return 3; }
        if (r == 0) break;
        if (n + (size_t)r > cap) { fprintf(stderr, "code too large\n"); return 4; }
        memcpy(buf + n, tmp, (size_t)r); n += (size_t)r;
    }

    const char *env = getenv("INIT_X1");
    unsigned long long init_x1 = env ? strtoull(env, NULL, 0) : 0ull;
    asm volatile ("mov x1, %0" :: "r"(init_x1));

    void (*fn)(void) = (void(*)(void))buf;
    fn();

    unsigned long long out_x1;
    asm volatile ("mov %0, x1" : "=r"(out_x1));
    printf("{\"x1\": %llu}\n", out_x1);
    return 0;
}
