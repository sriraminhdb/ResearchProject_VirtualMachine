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
    __builtin___clear_cache((char*)mem, (char*)mem + len);

    const char *s = getenv("INIT_X1");
    unsigned long long init_x1 = s ? strtoull(s, NULL, 0) : 0ULL;
    asm volatile("mov x1, %0" :: "r"(init_x1) : "x1");

    void (*fn)(void) = (void(*)(void))mem;
    fn();

    unsigned long long out_x1;
    asm volatile("mov %0, x1" : "=r"(out_x1));

    printf("{\"x1\": %llu}\n", out_x1);
    fflush(stdout);
    return 0;
}
