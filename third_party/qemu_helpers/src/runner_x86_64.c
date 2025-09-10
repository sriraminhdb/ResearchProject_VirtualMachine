#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    uint8_t buf[4096];
    ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
    if (len <= 0) return 1;

    void *mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return 2;
    memcpy(mem, buf, (size_t)len);

    const char *s = getenv("INIT_RBX");
    unsigned long long init_rbx = s ? strtoull(s, NULL, 0) : 0ULL;
    asm volatile("mov %0, %%rbx" :: "r"(init_rbx) : "rbx");

    void (*fn)(void) = (void(*)(void))mem;
    fn();

    unsigned long long out_rbx;
    asm volatile("mov %%rbx, %0" : "=r"(out_rbx));

    printf("{\"rbx\": %llu}\n", out_rbx);
    fflush(stdout);
    return 0;
}
