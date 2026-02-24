#include <stdio.h>
#include <errno.h>
#include <modbus.h>

int main() {
    modbus_t *ctx = modbus_new_tcp("127.0.0.1", 5020);
    if (!ctx) {
        printf("Failed to create context\n");
        return 1;
    }

    modbus_set_response_timeout(ctx, 5, 0);
    modbus_set_slave(ctx, 1);  /* Set unit ID to 1 */
    modbus_set_debug(ctx, TRUE);

    if (modbus_connect(ctx) == -1) {
        printf("Connect failed: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return 1;
    }
    printf("Connected!\n");

    uint16_t regs[10];
    int rc = modbus_read_registers(ctx, 0, 10, regs);
    printf("Read returned: %d\n", rc);

    if (rc == 10) {
        for (int i = 0; i < 10; i++) {
            printf("HR[%d] = %u\n", i, regs[i]);
        }
    } else {
        printf("Error: %s\n", modbus_strerror(errno));
    }

    modbus_close(ctx);
    modbus_free(ctx);
    return 0;
}
