# CVE-2023-36109
a poc for cve-2023-36109 
## request repo
```
git clone https://github.com/jerryscript-project/jerryscript.git
cd jerryscript
```

## build 
```
python ./tools/build.py --clean --debug --compile-flag=-m32 --compile-flag=-fno-omit-frame-pointer --compile-flag=-fno-common --compile-flag=-fsanitize=address --compile-flag=-g --strip=off --lto=off --error-messages=on --system-allocator=on --logging=on --line-info=on --stack-limit=20
```

## main reson 

buffer overflow at ecma_stringbuilder_append_raw in jerry-core/ecma/base/ecma-helpers-string.c:2609
