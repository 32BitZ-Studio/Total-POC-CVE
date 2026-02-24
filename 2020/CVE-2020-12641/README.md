# CVE-2020-12641: Command Injection via “_im_convert_path” Parameter in Roundcube Webmail

A Command Injection vulnerability exists in Roundcube versions before 1.4.4, 1.3.11 and 1.2.10.

Because the "_im_convert_path" does not perform sanitization/input filtering, an attacker with access to the Roundcube Installer can inject system commands in this parameter that will execute when any user opens any email containing a "non-standard" image.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://roundcube.net/news/2020/04/29/security-updates-1.4.4-1.3.11-and-1.2.10).

### Requirements:

This vulnerability requires:
<br/>
- Access to the Roundcube Webmail installer component
- Waiting for a Roundcube user to open an email containg a non-standard image

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2020-12641/blob/main/Roundcube%20Disclosures%20-%20CVE-2020-12641.pdf).
