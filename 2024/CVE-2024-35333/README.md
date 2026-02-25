# CVE-2024-35333

A stack buffer overflow vulnerability exists in the charset handling functionality of html2xhtml version 1.3. An attacker can exploit this vulnerability by providing a specially crafted input, which would lead to the overflow of the 'buf' variable located on the stack. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code or crash the application, leading to denial of service.

## Crash Out Phase
To reproduce the crash let's go to the project website and download the latest version 1.3.

Once we have the tar file, we can run `tar xvf XYZ.tar`

Run:
```
./configure
make
./html2xhtml poc.html
```

You should receive a segmentation fault. Let's analyze this with Address Sanitizer. 

Run:
```
make clean
make CFLAGS=-fsanitize=address
./html2xhtml poc.html
```

Receive the output:
```bash
=================================================================
==3468537==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffffffde70 at pc 0x7ffff7493fc4 bp 0x7fffffffdc00 sp 0x7fffffffd3a8
READ of size 86 at 0x7fffffffde70 thread T0
    #0 0x7ffff7493fc3 in __interceptor_memmem ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:686
    #1 0x5555555f5f35 in read_charset_decl /home/kenny/Downloads/html2xhtml-1.3/src/charset.c:680
    #2 0x5555555f7d89 in guess_charset /home/kenny/Downloads/html2xhtml-1.3/src/charset.c:508
    #3 0x5555555f7d89 in charset_auto_detect /home/kenny/Downloads/html2xhtml-1.3/src/charset.c:343
    #4 0x555555568d49 in main /home/kenny/Downloads/html2xhtml-1.3/src/html2xhtml.c:100
    #5 0x7ffff7029d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #6 0x7ffff7029e3f in __libc_start_main_impl ../csu/libc-start.c:392
    #7 0x55555556b914 in _start (/home/kenny/Downloads/html2xhtml-1.3/src/html2xhtml+0x17914)

Address 0x7fffffffde70 is located in stack of thread T0 at offset 544 in frame
    #0 0x5555555e86bf in read_charset_decl /home/kenny/Downloads/html2xhtml-1.3/src/charset.c:536

  This frame has 1 object(s):
    [32, 544) 'buf' (line 537) <== Memory access at offset 544 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:686 in __interceptor_memmem
Shadow bytes around the buggy address:
  0x10007fff7b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7b80: 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1 00 00
  0x10007fff7b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x10007fff7bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00[f3]f3
  0x10007fff7bd0: f3 f3 f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00
  0x10007fff7be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1
  0x10007fff7bf0: f1 f1 00 f3 f3 f3 00 00 00 00 00 00 00 00 00 00
  0x10007fff7c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007fff7c10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==3468537==ABORTING
```

## Root Cause Analysis

Let's take a look at the source code and review the vulnerable function: read_charset_decl(). The function is over 100 lines of code. 
We'll simplify it and take a look at this particular loop.

```c
  for (i = ini, len = 0; i < avail && len < SCAN_LEN; i += step, len++) {
    buf[len] = tolower(buffer[i]);
  }
```

This loop copies data from the buffer array to buf, converting characters to lower case as it goes. The problem is when avail is greater than SCAN_LEN and the loop does not check for the upper bounds of buf being exceeded. 

In order to mitigate there should be bounds checking to make sure len does not exceed SCAN_LEN. 


