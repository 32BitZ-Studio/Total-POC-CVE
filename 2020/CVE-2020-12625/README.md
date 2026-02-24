# CVE-2020-12625: Cross-Site Scripting via Malicious HTML Attachment in Roundcube Webmail

A Cross-Site scripting (XSS) vulnerability exists in Roundcube versions before 1.4.4, 1.3.11 and 1.2.10.

By leveraging the "<\![CDATA[...]]>" XML element in a mail with a "text/html" attachment, an attacker can bypass the Roundcube script filter and execute arbitrary malicious JavaScript in the victim's browser when the malicious email is clicked.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://roundcube.net/news/2020/04/29/security-updates-1.4.4-1.3.11-and-1.2.10).

### Requirements:

This vulnerability requires:
<br/>
- Waiting for a Roundcube user to open the email containg the XSS

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2020-12625/blob/main/Roundcube%20Disclosures%20-%20CVE-2020-12625.pdf).
