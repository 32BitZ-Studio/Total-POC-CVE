# Firmware Memory Leak

The code here aims to demonstrate the memory leaks in guest messages headers and the CPUID request guest message.

# Prerequisites

- Install rustup.
- Install a Linux kernel with SEV-SNP host support. I used a kernel with my a few of own patches https://github.com/Freax13/linux/tree/snp-host-v9-rfc-with-my-patches.

# Usage

1. Reboot the machine
2. Run `cargo make run run` in the `host` directory.
3. Observe the logs for leaked values start values of pAlignedPTReqPayload after firmware initialization.
4. Run `cargo make run run-with id 123` in the `host` directory. This launches a guest with an id auth block set to all 123.
5. Observe the logs for id block in the leaked values.
6. Start a SEV-ES guest.
7. Observed the logs for leaked launch data. Note that the values here will only appear if more than one page was submitted in a single command. This will only happen if the guest data as submittetd by QEMU is contigous in physical memory. This chances of this are not very good so it might take more than a dozen attemps to trigger this.

