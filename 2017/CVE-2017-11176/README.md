# cve-2017-11176
 Local Privilege Escalation
> develope on ubuntu 4.4.0-62 kernel
## about
My first try to code my own LPE exploit.

## developement line
[c2bbad5f471ef2b112f343fde1f4e7ff94fe28d1](https://github.com/DoubleMice/cve-2017-11176/commit/c2bbad5f471ef2b112f343fde1f4e7ff94fe28d1)

triger kernel uaf

[d2872d5c0d642e20c807a960f99d9533dde5d809](https://github.com/DoubleMice/cve-2017-11176/commit/d2872d5c0d642e20c807a960f99d9533dde5d809)

now,we can use another thread to unblock main thread without systemtap.

## todo
* exploit to get root shell

## reference
- [lexfo:linux-kernel-exploitation](https://blog.lexfo.fr/)

    While this guy's work was based on Debian8.6.0(kernel version:3.16.36).
    But honestly,his articles are very nice to the freshman who wants to enjoy kernel exploit.
    Thanks.