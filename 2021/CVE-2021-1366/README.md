# CVE-2021-1366
Cisco AnyConnect Posture (HostScan) Local Privilege Escalation: CVE-2021-1366
A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to perform a DLL hijacking attack on an affected device if the VPN Posture (HostScan) Module is installed on the AnyConnect client.\
This POC sends 2 `priv_file_copy ` IPC commands to the Cisco Security Service `ciscod.exe` to copy 2 DLLs to the `C:\Program Files(x86)\Cisco\Cisco HostScan\bin\` directory. Upon the restart of the Cisco Security Service, `ciscod.exe` loads the malicious dbghelp.dll (using DLL proxying). 
 
## Prerequisites
* Create a `Cisco\Cisco HostScan` directory in the `%TEMP%` folder
* Create a malicious DLL that will be used for DLL proxying (see [https://itm4n.github.io/dll-proxying/](https://itm4n.github.io/dll-proxying/))
* Name the dll as `dbghelp.dll` and copy it to the folder `%TEMP%\Cisco\Cisco HostScan`
* Copy the Windows original `"C:\Windows\SysWOW64\dbghelp.dll"` to the folder `%TEMP%\Cisco\Cisco HostScan` and rename it to `dbghelp_orig.dll`
* Prepare a process hollowing tool (e.g. [https://github.com/ivkin25/Process-Hollowing](https://github.com/ivkin25/Process-Hollowing))

## Instructions
* Compile this POC
* Run the following command which will perform a process hollowing of `ciscod.exe` and replace it with this POC process that sends the 2 IPC commands
```
ProcessHollowing.exe C:\Program Files(x86)\Cisco\Cisco HostScan\bin\ciscod.exe CVE-2021-1366.exe
```
* 2 DLLs, `dbghelp.dll` and `dbghelp_orig.dll`, should be copied to `C:\Program Files(x86)\Cisco\Cisco HostScan\bin\`
* Restart the service and wait for the malicious DLL to be loaded

# References
[https://www.coresecurity.com/core-labs/articles/analysis-cisco-anyconnect-posture-hostscan-local-privilege-escalation-cve-2021](https://www.coresecurity.com/core-labs/articles/analysis-cisco-anyconnect-posture-hostscan-local-privilege-escalation-cve-2021)\
[https://www.coresecurity.com/core-labs/advisories/cisco-anyconnect-posture-hostscan-security-service-local-privilege-escalation](https://www.coresecurity.com/core-labs/advisories/cisco-anyconnect-posture-hostscan-security-service-local-privilege-escalation)\
[https://itm4n.github.io/dll-proxying/](https://itm4n.github.io/dll-proxying/)\
[https://github.com/ivkin25/Process-Hollowing](https://github.com/ivkin25/Process-Hollowing)
