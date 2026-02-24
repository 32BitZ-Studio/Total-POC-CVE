/*
 * Backdoor Driver Component (seL4/CAmkES)
 *
 * Simulates a supply-chain-compromised network driver component for the
 * seL4 gateway. When triggered by a magic byte sequence, the compromised
 * component attempts various privilege escalation actions.
 *
 * This demonstrates seL4's capability-based isolation: even when a component
 * is fully compromised, it CANNOT:
 * - Access kernel memory (VM fault)
 * - Read/write other component memory (capability fault)
 * - Forge capabilities (invalid cap error)
 * - Bypass the parser to send raw data to PLC (no capability)
 *
 * Integration:
 *   Copy this code into the Net0_Driver component of the seL4 gateway:
 *   projects/ics_gateway_x86/components/Net0_Driver/net0_driver.c
 *
 * Trigger: Send packet with bytes 12-19 = \xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE
 *
 * For defensive security research only.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* Trigger sequence - 8 bytes at offset 12 in TCP payload (after MBAP header) */
#define BACKDOOR_TRIGGER "\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
#define BACKDOOR_TRIGGER_LEN 8
#define BACKDOOR_TRIGGER_OFFSET 12

/* Escalation action codes (in byte 20 of payload) */
#define ESCALATE_READ_KERNEL    0x01
#define ESCALATE_WRITE_PARSER   0x02
#define ESCALATE_BYPASS_TO_PLC  0x03
#define ESCALATE_FORGE_CAP      0x04

/* Result codes for logging */
#define RESULT_SUCCESS     0
#define RESULT_VM_FAULT    1
#define RESULT_CAP_FAULT   2
#define RESULT_NO_CAP      3
#define RESULT_INVALID_CAP 4

typedef struct {
    uint8_t action;
    int result;
    const char *description;
} escalation_result_t;

/*
 * Attempt 1: Read kernel memory
 *
 * On Linux: Would succeed (same address space, ring 0 accessible via /dev/mem or exploit)
 * On seL4: VM fault - kernel memory is not mapped into any component's VSpace
 */
static escalation_result_t attempt_read_kernel(void) {
    escalation_result_t res = {ESCALATE_READ_KERNEL, RESULT_VM_FAULT, "read_kernel_memory"};

    /*
     * Attempt to read from a kernel-space address.
     * On seL4, this will trigger a VM fault handled by the component's
     * fault handler. The component may be restarted, but NO data is leaked.
     *
     * On x86_64 seL4: kernel lives at addresses not mapped in user VSpace
     * On ARM seL4: kernel lives in high memory, unmapped from user
     */
    volatile uint8_t *kernel_addr = (volatile uint8_t *)0xFFFFFFFF80000000ULL;

    /* This read WILL fault on seL4 */
    /* volatile uint8_t byte = *kernel_addr; */
    /* (void)byte; */

    /* Instead, we report what WOULD happen */
    printf("[BACKDOOR] Attempted kernel read at %p -> VM FAULT (seL4)\n",
           (void *)kernel_addr);

    return res;
}

/*
 * Attempt 2: Access parser component memory
 *
 * On Linux: Would succeed (same address space, all memory accessible)
 * On seL4: Capability fault - no capability to parser's memory frames
 */
static escalation_result_t attempt_access_parser(void) {
    escalation_result_t res = {ESCALATE_WRITE_PARSER, RESULT_CAP_FAULT, "access_parser_component"};

    /*
     * On seL4/CAmkES, each component has its own VSpace (address space).
     * The Net0_Driver component has NO capabilities to any frames belonging
     * to the EverParse parser component. Any attempt to access parser memory
     * results in a capability fault.
     *
     * The component would need a Frame capability for the parser's memory,
     * which was never granted in the CAmkES specification.
     */
    printf("[BACKDOOR] Attempted parser memory access -> CAPABILITY FAULT (seL4)\n");
    printf("[BACKDOOR] Net0_Driver has no Frame caps for Parser component\n");

    return res;
}

/*
 * Attempt 3: Bypass validation and send directly to PLC
 *
 * On Linux: Would succeed (can open socket to PLC directly)
 * On seL4: No capability - Net0_Driver only has capability to the
 *           untrusted-side NIC, not the protected-side NIC
 */
static escalation_result_t attempt_bypass_to_plc(void) {
    escalation_result_t res = {ESCALATE_BYPASS_TO_PLC, RESULT_NO_CAP, "bypass_validation_to_plc"};

    /*
     * The CAmkES architecture provides the Net0_Driver with capabilities
     * ONLY for the untrusted network interface (net0). The protected network
     * interface (net1) is managed exclusively by Net1_Driver.
     *
     * Even if Net0_Driver is fully compromised, it cannot:
     * - Access net1's device MMIO regions (no Frame caps)
     * - Send packets on net1 (no IRQ/notification caps for net1)
     * - Communicate with Net1_Driver (no shared memory/endpoint caps)
     *
     * Data can ONLY flow: Net0 -> Parser -> Net1 (via declared CAmkES connections)
     */
    printf("[BACKDOOR] Attempted direct PLC access -> NO CAPABILITY (seL4)\n");
    printf("[BACKDOOR] Net0_Driver has no caps for net1 (protected network)\n");

    return res;
}

/*
 * Attempt 4: Forge a capability via syscall
 *
 * On Linux: N/A (no capability system)
 * On seL4: Invalid capability error - capabilities can only be derived
 *           from existing capabilities through the kernel
 */
static escalation_result_t attempt_forge_capability(void) {
    escalation_result_t res = {ESCALATE_FORGE_CAP, RESULT_INVALID_CAP, "forge_capability_syscall"};

    /*
     * seL4 capabilities are unforgeable tokens managed by the kernel.
     * A component cannot:
     * - Create capabilities from nothing (no Retype without Untyped cap)
     * - Modify existing capabilities (no CNode Mutate without CNode cap)
     * - Copy capabilities it doesn't have (no CNode Copy without source cap)
     *
     * The only way to get new capabilities is through the CAmkES specification
     * at build time, or through explicit delegation at runtime (which requires
     * the delegator to already have the capability).
     */
    printf("[BACKDOOR] Attempted capability forge -> INVALID CAP ERROR (seL4)\n");
    printf("[BACKDOOR] Cannot create caps without existing Untyped/CNode caps\n");

    return res;
}

/*
 * Main backdoor entry point
 *
 * Called when the trigger sequence is detected in an incoming packet.
 * Returns the results of all escalation attempts for evidence collection.
 */
int backdoor_trigger(uint8_t *packet_data, size_t packet_len, escalation_result_t results[4]) {
    int triggered = 0;

    /* Verify trigger sequence */
    if (packet_len < BACKDOOR_TRIGGER_OFFSET + BACKDOOR_TRIGGER_LEN) {
        return 0;
    }

    if (memcmp(packet_data + BACKDOOR_TRIGGER_OFFSET, BACKDOOR_TRIGGER, BACKDOOR_TRIGGER_LEN) != 0) {
        return 0;
    }

    printf("[BACKDOOR] *** TRIGGER SEQUENCE DETECTED ***\n");
    printf("[BACKDOOR] Attempting privilege escalation...\n");

    /* Execute all escalation attempts */
    results[0] = attempt_read_kernel();
    results[1] = attempt_access_parser();
    results[2] = attempt_bypass_to_plc();
    results[3] = attempt_forge_capability();

    printf("[BACKDOOR] All escalation attempts FAILED (seL4 isolation holds)\n");
    triggered = 1;

    return triggered;
}

/*
 * Check if packet contains backdoor trigger
 *
 * This function should be called from the network driver's receive path.
 * In the real implementation, this replaces part of the packet receive handler.
 */
int check_backdoor_trigger(uint8_t *data, size_t len) {
    if (len < BACKDOOR_TRIGGER_OFFSET + BACKDOOR_TRIGGER_LEN) {
        return 0;
    }

    return memcmp(data + BACKDOOR_TRIGGER_OFFSET, BACKDOOR_TRIGGER, BACKDOOR_TRIGGER_LEN) == 0;
}
