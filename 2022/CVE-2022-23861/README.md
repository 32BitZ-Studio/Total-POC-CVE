# CVE-2022-23861: Multiple Stored Cross-Site Scripting in YSoft SafeQ

Multiple fields in the YSoft SafeQ web application can be used to inject malicious inputs that, due to a lack of output sanitization, result in the execution of arbitrary JS code. These fields can be leveraged to perform XSS attacks on legitimate users accessing the SafeQ web interface.

### Collaboration:

This vulnerability was found in collaboration with Marian-Razvan Ilisanu.

### NVD Disclosure:

The disclosure for this vulnerability can be found [here](https://nvd.nist.gov/vuln/detail/CVE-2022-23861).

### Requirements:

This vulnerability requires:
<br/>
- Valid user credentials in order to access and edit the vulnerable fields

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2022-23861/blob/main/SafeQ%20-%20CVE-2022-23861.pdf).
