# MAL-008: SSHtranger Things (CVE-2019-6111, CVE-2019-6110) in Cisco SD-WAN

Cisco SD-WAN v20.4.2.1 uses an old version of SSH (OpenSSH_7.6p1) that is susceptible to the “SSHtranger Things” attack. If a victim tries to connect to a malicious/compromised SSH server this attack may be used to write/overwrite sensitive files.

By overwriting sensitive script files (e.g. “.bashrc”) this may allow an unauthenticated attacker to obtain Remote Code Execution (RCE) on the victim’s system.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://bst.cisco.com/quickview/bug/CSCwb16963).

### Requirements:

This vulnerability requires:
<br/>
- Successful SSH MITM
  <br/>OR
- Social engineering to convince a legitimate SD-WAN user to connect to a malicious SSH server

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/MAL-008/blob/main/Cisco%20SD-WAN%20-%20SSHtranger%20Things.pdf).

### Additional Information:

[PoC for CVE-2019-6111 and CVE-2019-6110](https://gist.github.com/mehaase/63e45c17bdbbd59e8e68d02ec58f4ca2)
