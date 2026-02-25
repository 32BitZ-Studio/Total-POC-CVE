# CVE-2022-25813: FreeMarker Server-Side Template Injection in Apache OfBiz

By inserting malicious content in a message’s “Subject” field, an attacker may perform SSTI (Server-Side Template Injection) attacks, which can leverage FreeMarker exposed objects to bypass restrictions and obtain RCE (Remote Code Execution).

<strong>Note:</strong> Although this vulnerability requires a valid user’s interaction to trigger the SSTI, the malicious payload can be sent by any unauthenticated attacker that creates an e-commerce account.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://lists.apache.org/thread/h9k33c7x69jzwczdvdj15xdqp3y5jw20).

### Requirements:

This vulnerability requires:
<br/>
- Registering a new user or valid user credentials
- User interaction of a administrative user

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2022-25813/blob/main/Apache%20OfBiz%20-%20CVE-2022-25813.pdf).

### Additional Resources:

Initial vulnerability [GHSL-2020-070 and blogpost](https://securitylab.github.com/advisories/GHSL-2020-070-apache_ofbiz/) by [Alvaro "pwntester" Munoz](https://github.com/pwntester) that inspired the SSTI research and finding of this vulnerability.
