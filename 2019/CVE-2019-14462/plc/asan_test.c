/*
 * Simple ASAN test - guaranteed to trigger heap-buffer-overflow
 */

#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== ASAN Test ===\n\n");

    /* Allocate 10 bytes */
    char *buf = malloc(10);
    printf("[*] Allocated 10 bytes at %p\n", (void*)buf);

    /* Write within bounds - OK */
    buf[0] = 'A';
    buf[9] = 'Z';
    printf("[*] Wrote within bounds - OK\n");

    /* Read out of bounds - ASAN should catch this! */
    printf("[*] About to read buf[20] (out of bounds)...\n");
    char c = buf[20];  /* <-- ASAN ERROR HERE */
    printf("[!] Read buf[20] = %c (0x%02x)\n", c, (unsigned char)c);

    free(buf);
    printf("[*] Done\n");

    return 0;
}
