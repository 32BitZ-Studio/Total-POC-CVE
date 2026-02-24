# CVE-2014-4076 PoC

This proof of concept directly copied from its [original python version](http://www.exploit-db.com/exploits/35936/) and rewritten in C++.

## Build

This project is built with Visual Studio 2013 Update 4.

## Notice

Only users that in Administrators group can open the device and perform IO controls, which means **the exploit only escalate Administrators to SYSTEM, and does not help in a webshell environment at all**.

Special thanks to [@KingsleyChen](https://github.com/kingsamchen) for help.