# CVE-2019-14678: XML External Entity in SAS XML Mapper

SAS XML Mapper 9.45 has an XML External Entity (XXE) vulnerability that can be leveraged by malicious attackers in multiple ways. Examples are Local File Reading, Out Of Band File Exfiltration, Server Side Request Forgery, and/or Potential Denial of Service attacks. This vulnerability also affects the XMLV2 LIBNAME engine when the AUTOMAP option is used.

### Vendor Disclosure:

The vendor's disclosure and fix for this vulnerability can be found [here](https://support.sas.com/kb/64/719.html).

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2019-14678/blob/main/SAS%20XML%20Mapper%20-%20CVE-2019-14678.pdf).

### Additional Resources:

[XXE OoB Attack](https://www.acunetix.com/blog/articles/band-xml-external-entity-oob-xxe/)

[XML LOL Bomb Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
