#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(void) {
    size_t cap = 1 << 16;
    uint8_t *buf = mmap(NULL, cap, PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 2; }

    size_t n = 0;
    uint8_t tmp[4096];
    for (;;) {
        ssize_t r = read(0, tmp, sizeof tmp);
        if (r < 0) { perror("read"); return 3; }
        if (r == 0) break;
        if (n + (size_t)r > cap) { fprintf(stderr, "code too large\n"); return 4; }
        memcpy(buf + n, tmp, (size_t)r); n += (size_t)r;
    }

    const char *env = getenv("INIT_RBX");
    unsigned long long init_rbx = env ? strtoull(env, NULL, 0) : 0ull;
    asm volatile ("mov %0, %%rbx" :: "r"(init_rbx) : "rbx");

    void (*fn)(void) = (void(*)(void))buf;
    fn();

    unsigned long long out_rbx;
    asm volatile ("mov %%rbx, %0" : "=r"(out_rbx));

    printf("{\"rbx\": %llu}\n", out_rbx);
    return 0;
}