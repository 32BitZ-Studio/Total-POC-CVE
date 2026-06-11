from keystone import *

"""
   0x000024bb7daca9e7:  4c 89 5d c8     mov    QWORD PTR [rbp-0x38],r11
   0x000024bb7daca9eb:  49 bb 00 c0 ad ba ef be ad de   movabs r11,0xdeadbeefbaadc000
   0x000024bb7daca9f5:  4c 89 5d c0     mov    QWORD PTR [rbp-0x40],r11
   0x000024bb7daca9f9:  49 bb 00 c0 ad ba ef be ad de   movabs r11,0xdeadbeefbaadc000
   0x000024bb7dacaa03:  4c 89 5d b8     mov    QWORD PTR [rbp-0x48],r11
   0x000024bb7dacaa07:  49 bb 00 c0 ad ba ef be ad de   movabs r11,0xdeadbeefbaadc000
"""

"""
   # To jump around the wrapping bytes
   $ rasm2 -a x86 -b 64 "jmp 9"
   eb07
"""

CODES = [
    "mov rax, [rsp + 0x28]",
    "mov rdi, [rsp + 0x30]",
    "mov rsi, [rsp + 0x38]",
    "mov rdx, [rsp + 0x40]",
    "syscall"
]

ks = Ks(KS_ARCH_X86, KS_MODE_64)

for code in CODES:
    print('')
    encoding, count = ks.asm(code)
    assembled_bytes = bytearray(encoding)
    assembled_bytes.reverse()  # For js consumption
    print("// {code}\n0x07eb{encoding}bd, // Length={length}".format(
        encoding=assembled_bytes.hex(),
        length=len(encoding),
        code=code))
