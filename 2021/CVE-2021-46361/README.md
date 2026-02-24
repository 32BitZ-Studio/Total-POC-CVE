# CVE-2021-46361: FreeMarker Restriction Bypass in Magnolia CMS

An issue in the FreeMarker Filter of Magnolia CMS v6.2.11 and below allows attackers to bypass security restrictions and execute arbitrary code via a crafted FreeMarker payload.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://docs.magnolia-cms.com/product-docs/6.2/Releases/Release-notes-for-Magnolia-CMS-6.2.12.html#_security_advisory).

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2021-46361/blob/main/Magnolia%20CMS%20-%20CVE-2021-46361.pdf).

### Additional Resources:

The SSTI gadget used to escape the FreeMarker sandbox was inspired from this [article](https://www.synacktiv.com/publications/exploiting-cve-2021-25770-a-server-side-template-injection-in-youtrack) by [Vincent Herbulot of Synacktiv](https://www.synacktiv.com/en/our-team/pentest)
