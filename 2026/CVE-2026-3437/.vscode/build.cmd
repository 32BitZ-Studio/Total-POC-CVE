@echo off
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    call "%%i\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
)
if not defined VCINSTALLDIR (
    echo ERROR: No Visual Studio installation with VC++ tools found.
    echo Install Visual Studio with the "Desktop development with C++" workload.
    exit /b 1
)
