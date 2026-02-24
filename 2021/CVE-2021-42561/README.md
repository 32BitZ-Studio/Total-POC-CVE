# CVE-2021-42561: Command Injection via the Human Plugin in MITRE Caldera

In Caldera (versions <=2.8.1) the Human plugin passes the unsanitized name parameter to a python "os.system" function. This allow attackers to use shell metacharacters (e.g. backticks "``" or dollar parenthesis "$()" ) in order to escape the current command and execute arbitrary shell commands. 

### Vendor Disclosure:

The vendor's disclosure for this vulnerability can be found [here](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42561).

### Requirements:

This vulnerability requires:
<br/>
- Valid user credentials

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/CVE-2021-42561/blob/main/Caldera%20-%20CVE-2021-42561.pdf).
