 section .text
    global _start

_start:

    jmp short string

    code:
    pop rsi
    mov rax, 1 ; sys_write
    mov rdi, 1 ; stdout
    mov rdx, 28 ; str len
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

    string:
    call code
    db  'The exploit finished successfully!',0x0A