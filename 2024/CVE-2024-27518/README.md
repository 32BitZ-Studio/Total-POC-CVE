# CVE-2024-27518 - SUPERAntiSpyware Professional X LPE PoC

This vulnerability was discovered and disclosed by M. Akil Gündoğan from Secunnix Vulnerability Research Team. This repository will hold the proof-of concept and advisories.

# Details:

- **Product:** SUPERAntiSpyware Professional X and all editions.
- **Affected versions:** <=10.0.1262 and lastest version 10.0.1264
- **CVE ID:** CVE-2024-27518
- **Operating System:** All supported Windows versions, tested on Windows 10 Pro
- **State:** Public responsible disclosure.
- **Release Date:** 03.04.2024

# Vulnerability Description:

**SUPERAntiSpyware Professional X 10.0.1262** is vulnerable to local privilege escalation because it allows unprivileged users to restore a malicious DLL from quarantine into the **"C:\Program Files\SUPERAntiSpyware"** folder via an NTFS directory junction, as demonstrated by a crafted version.dll file that is detected as malware. Since **SASCore64.exe** has a DLL Hijacking vulnerability for "version.dll", a shell is obtained as **NT AUTHORITY\SYSTEM** after system reboot.

Technical details and step by step Proof of Concept's (PoC):

- **1** - ​A malicious `version.dll` file containing shellcode is created.
- **2** - If the generated shellcode containing `version.dll` is not already detected by SUPERAntiSpyware, it is combined with another malicious file in ".zip" with the command `copy /b version_created.dll + malicious.zip version.dll` to be detected as malicious. In this way, the created ".dll" file can be detected as malicious by SUPERAntiSpyware and quarantined.
- **3** - Create a new folder and copy the prepared `version.dll` into it. Then the folder is scanned and SUPERAntiSpyware quarantines the DLL.
- **4** - Using `CreateMountPoint.exe` among the "Symbolic Link Testing" tools provided by Google, the path where `version.dll` is quarantined is mounted in the `C:\Program Files\SUPERAntiSpyware` directory. These tools are available at the following link (https://github.com/googleprojectzero/symboliclink-testing-tools) or you can use the mklink command to do the same thing. 
- **5** - When the quarantined "version.dll" is restored, it will be copied to SUPERAntiSpyware's directory. After the system reboots, **SASCore64.exe** will execute the shellcode in "version.dll" and open a session with `NT AUTHORITY\SYSTEM` privileges for the attacker.

# Video:
[<img src="https://i.ytimg.com/vi/FM5XlZPdvdo/maxresdefault.jpg" width="75%">](https://www.youtube.com/watch?v=FM5XlZPdvdo)

# Mitigations:

Unfortunately, it is not available. We recommend uninstalling SUPERAntiSpyware until the vulnerability is fixed. 

# Timeline:

- 18.02.2024 - Vulnerability reported via email but vendor refused to fix it.
- 03.04.2024 - Full disclosure.

# References:
- Vendor: https://www.superantispyware.com/
- CVE: https://www.cve.org/CVERecord?id=CVE-2024-27518
