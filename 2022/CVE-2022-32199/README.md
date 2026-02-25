# CVE-2022-32199
ScriptCase <= 9.9.008 is vulnerable to
Arbitrary File Deletion by an admin
via a directory traversal sequence in the file parameter

How to use:
> python CVE-2022-32199.py -t 127.0.0.1 -u admin -p admin -path windows/win.ini



Example of deleting file in the root directory

![Image alt](https://github.com/Toxich4/CVE-2022-32199/blob/main/src/PoC.gif)
