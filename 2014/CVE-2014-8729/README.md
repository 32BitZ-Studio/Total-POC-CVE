# TORQUE-Resource-Manager-2.5.x-2.5.13-stack-based-buffer-overflow-exploit-CVE-2014-8729-CVE-2014-878
- Exploit Title: TORQUE Resource Manager 2.5.x-2.5.13 stack based buffer overflow
- Date: 10 Nov 2014
- Exploit Author: @inso - Moussajee Thomas, @socks - Laurenceau Gary
- Vulnerability discovered by: Moussajee Thomas, Laurenceau Gary
- CVE: CVE-2014-8729, CVE-2014-8787
- Vendor Homepage: http://www.adaptivecomputing.com/
- Software Link: http://www.adaptivecomputing.com/support/download-center/torque-download/
- Version tested: 2.5.12
- Version affected : 2.5.x - 2.5.13
- Tested on: Debian 32bit with ASLR disabled

- ROP on exit(42) with control of EAX register
- can be customisable (uncoment line) for reverse shellcode execution if NX is disabled
