# CVE-2021-20253: Privilege Escalation via Job Isolation Escape in Ansible Tower

A flaw was found in ansible-tower. The default installation is vulnerable to Job Isolation escape allowing an attacker to elevate the privilege from a low privileged user to the awx user from outside the isolated environment. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://access.redhat.com/security/cve/cve-2021-20253).

### Requirements:

This vulnerability requires:
<br/>
- Being able to execute commands in isolation environment in Ansible Tower
- Having low privileged access to the OS

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2021-20253/blob/main/Ansible%20Tower%20Disclosures%20-%20CVE-2021-20253.pdf).
