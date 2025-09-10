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
    void *buf = mmap(NULL, SZ, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    size_t off = 0;
    while (off < SZ) {
        ssize_t n = read(STDIN_FILENO, (char*)buf + off, SZ - off);
        if (n < 0) { perror("read"); return 2; }
        if (n == 0) break;
        off += (size_t)n;
    }

    uint64_t in_rbx = read_env_u64("INIT_RBX");
    uint64_t in_rdx = read_env_u64("INIT_RDX");
    uint64_t out_rbx = 0, out_rdx = 0;
    void (*fn)(void) = (void (*)(void))buf;

    asm volatile(
    "push %%rbx              \n\t"
    "mov  %[irbx], %%rbx     \n\t"
    "mov  %[irdx], %%rdx     \n\t"
    "call *%[target]         \n\t"
    "mov  %%rbx, %[orbz]     \n\t"
    "mov  %%rdx, %[ordz]     \n\t"
    "pop  %%rbx              \n\t"
    : [orbz] "=&r"(out_rbx), [ordz] "=&r"(out_rdx)    // early‑clobber outputs
    : [irbx] "r"(in_rbx), [irdx] "r"(in_rdx), [target] "r"(fn)
    : "rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11","cc","memory"
    );


    printf("rbx=%" PRIu64 "\n", out_rbx);
    printf("rdx=%" PRIu64 "\n", out_rdx);
    fflush(stdout);
    return 0;
}
