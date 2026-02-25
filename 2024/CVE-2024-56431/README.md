```
# Compile application source code
CFLAGS="-fsanitize=address -fsanitize=undefined -g -O1"  CXXFLAGS="-fsanitize=address -fsanitize=undefined -g -O1" LDFLAGS="-fsanitize=address" ./configure

make 

# Compile PoC source code
g++ fuzzer.cpp -o poc -I include/ lib/.libs/libtheora.a -fsanitize=address -fsanitize=undefined

# Executing the PoC
UBSAN_OPTIONS=print_stacktrace=1 ./poc
```

