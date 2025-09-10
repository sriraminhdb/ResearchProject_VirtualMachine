#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

static uint64_t read_env_u64(const char *name) {
    const char *s = getenv(name);
    return (s && *s) ? strtoull(s, NULL, 0) : 0ull;
}

int main(void) {
    const size_t SZ = 1u << 16;
    void *buf = mmap(NULL, SZ, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    size_t off = 0;
    while (off < SZ) {
        ssize_t n = read(STDIN_FILENO, (char*)buf + off, SZ - off);
        if (n < 0) { perror("read"); return 2; }
        if (n == 0) break;
        off += (size_t)n;
    }

    uint64_t in_x1 = read_env_u64("INIT_X1");
    uint64_t in_x2 = read_env_u64("INIT_X2");
    uint64_t out_x1 = 0, out_x2 = 0;
    void (*fn)(void) = (void (*)(void))buf;

    asm volatile(
    "mov x1, %[in1]\n\t"
    "mov x2, %[in2]\n\t"
    "blr %[target]\n\t"
    "mov %[o1], x1\n\t"
    "mov %[o2], x2\n\t"
    : [o1] "=&r"(out_x1), [o2] "=&r"(out_x2)          
    : [in1] "r"(in_x1), [in2] "r"(in_x2), [target] "r"(fn)
    : "x0","x1","x2","x3","x4","x5","x6","x7",
      "x8","x9","x10","x11","x12","x13","x14",
      "x15","x16","x17","x18","x30","memory"
    );

    printf("x1=%" PRIu64 "\n", out_x1);
    printf("x2=%" PRIu64 "\n", out_x2);
    fflush(stdout);
    return 0;
}
