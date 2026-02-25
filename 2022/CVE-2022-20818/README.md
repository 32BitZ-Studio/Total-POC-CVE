# CVE-2022-20818: Local Privilege Escalation via Partial File Read in Cisco SD-WAN

The “config -> load” feature from Viptela SSH shell uses “wget” to fetch remote “command” files over FTP. By hosting a malicious FTP server and replacing the local files created by wget with symlinks, an attacker can abuse the “root” privileges with which the commands are run to read the first line of arbitrary files.

By reading the secret from “/etc/confd/confd_etc_secret”, the attacker is able to obtain an interactive shell with “root” privileges on the machine.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sd-wan-priv-E6e8tEdF.html).

### Requirements:

This vulnerability requires:
<br/>
- Access to the Viptela shell (e.g. via SSH)
<br/>OR
- Access to the local system

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2022-20818/blob/main/Cisco%20SD-WAN%20-%20CVE-2022-20818.pdf).

### Additional Resources:

[Article by Johnny "straight_blast" Yu](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77) detailing how to use the "/etc/confd/confd_etc_secret" secret + GDB to gain a root shell

The original ftp_server script used and modified in this exploit was taken from [here](https://github.com/jacklam718/ftp)
