# CVE-2019-17497

[CVE Details](https://www.cvedetails.com/cve/CVE-2019-17497/)

> PDF-XChange Editor before 8.0.330.0 has an NTLM SSO hash theft vulnerability using crafted FDF or XFDF files (a related issue to CVE-2018-4993). For example, an NTLM hash is sent for a link to \\attacker.loca\C$\eee.pdf without user interaction. 

[Original Writeup](https://raw.githubusercontent.com/ponypot/cve/master/pdfXChangeEditor_FDFInclusions.pdf)

Since the original writeup didn't include the POC as files, I recreated them myself.

Replace `attacker.local` in the files with the IP address of your Attacking Server.