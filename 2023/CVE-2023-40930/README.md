# Introduction
 It's an introduction on how to set up CVE-2023-40930 Repetition Enviroment
 
 Learn more about this CVE problem in "issue detail.pdf"
# Set up
## general
You can use rasperry pi zero 2W or any other ARM64(ARM32 also) arch devices to set up this enviroment,this can be also set up on Android rooted devices
## How to set up
### for no-android devices
Make a directory path which is "/system/lib",and copy the "lib" DIR in this program to /system/lib.
And then make a directory path which is "/system/bin",and copy the "blkid" and "linker" to this path.
After that,you can insert your Bad Udisk and exec "/system/bin/blkid" to repeat this problem
### for android devices
Just add all the files in the "lib" DIR to /system/lib , then move the "blkid" to an X-Permission path, after that you can also repeat this problem by
insert your Bad Udisk and exec "/system/bin/blkid".
# More contact
For more contact ,send email to namelessyyds@gmail.com
