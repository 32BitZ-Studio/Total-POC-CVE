# dir-3040 Denial of Service
Dir-3060 might also be affected as they share many components from same firmware.

Tested on latest firmware 1.20b03a hotfix

ftp server user access page by default is configured for any user with write privileges to write directly to ram instead of restricting to usb drives only.

There are no out of bound or buffer overflow checks in place in latest firmware for this issue.

After writing(filling) available memory system will crash and reboot.

User doesnt need to have administrator privileges to perform the attack.

proof of concept in detail with pictures below

D-link was contacted and strongly denied presence of the issue because they couldnt reproduce the issue. All other nonsensical resolutions were denied by me.

![Screenshot](IMG_7075.png)

![Screenshot](IMG_7076.png)

![Screenshot](IMG_7077.png)

Showing default config for new user

![Screenshot](IMG_7078.png)

Check for available memory in syslog

![Screenshot](IMG_7079.png)

![Screenshot](IMG_7080.png)

Creating 300mb file with dd accessing ftp as a user with read and write privileges changing to / and writing the file

![Screenshot](IMG_7081.png)

![Screenshot](IMG_7083.png)

![Screenshot](IMG_7082.png)


As soon as available free memory is filled system will crash and reboot.

This can be reproduced with any size usb flash.

There is no patch or solution yet.
