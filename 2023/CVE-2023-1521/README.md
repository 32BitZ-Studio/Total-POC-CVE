## PoC

```bash
gcc -shared -o libpoc.so poc.c -fPIC
export LD_PRELOAD=fullpath_to_libpoc.so
sccache gcc foo.c -o foo
```