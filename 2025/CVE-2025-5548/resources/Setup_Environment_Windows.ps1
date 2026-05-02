# ---------------------------------------------------------------------------------------------------------------------------------------------------------

# =========================================================================================================================================================
# Debugging, Reversing and Exploiting Environment (Windows PowerShell)
# TheMalwareGuardian
# =========================================================================================================================================================



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
$ConfigURLs = @{
	# My
	"URL_My_Linkedin" = "https://www.linkedin.com/in/vazquez-vazquez-alejandro/"
	"URL_My_Repository" = "https://github.com/TheMalwareGuardian/"
	"URL_My_RepositoryBinaryExploitation" = "https://github.com/TheMalwareGuardian/Exploit-the-Binary"
	"URL_My_RepositoryThisOne" = "https://github.com/TheMalwareGuardian/Debugging-Reversing-Exploiting-Environment"
	# Requirements
	"URL_Requirements_Git" = "https://github.com/git-for-windows/git/releases/download/v2.51.0.windows.2/Git-2.51.0.2-64-bit.exe"
	"URL_Requirements_WindowsSDK" = "https://download.microsoft.com/download/9d2b0e7e-c04f-402c-8ce6-51f1e56028e8/KIT_BUNDLE_WINDOWSSDK_MEDIACREATION/winsdksetup.exe"
	"URL_Requirements_JavaJDK" = "https://download.oracle.com/java/25/latest/jdk-25_windows-x64_bin.exe"
	"URL_Requirements_Netcat" = "https://nmap.org/dist/nmap-7.98-setup.exe"
	"URL_Requirements_Python3x64" = "https://www.python.org/ftp/python/3.9.0/python-3.9.0-amd64.exe"
	"URL_Requirements_Python2x64" = "https://www.python.org/ftp/python/2.7.18/python-2.7.18.amd64.msi"
	"URL_Requirements_VisualStudio2019" = "https://download.visualstudio.microsoft.com/download/pr/7c09e2e8-2b3e-4213-93ab-5646874f8a2b/0ac797413a56c6b2772f48a567a32cdddd3b739f5b2af649fcf90be4245762ff/vs_Community.exe"
	# IDEs
	"URL_IDEs_Notepad" = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.8.5/npp.8.8.5.Installer.x64.exe"
	"URL_IDEs_VisualStudioCode" = "https://vscode.download.prss.microsoft.com/dbazure/download/stable/7d842fb85a0275a4a8e4d7e040d2625abbf7f084/VSCodeUserSetup-x64-1.105.1.exe"
	"URL_IDEs_PycharmCommunity" = "https://download.jetbrains.com/python/pycharm-2025.2.3.exe"
	# Dynamic Debuggers
	"URL_Debuggers_ImmunityDebugger" = "https://raw.githubusercontent.com/TheMalwareGuardian/Exploit-the-Binary/refs/heads/main/00%20Tools/ImmunityDebugger_1_85_setup.zip"
	"URL_Debuggers_x64dbg" = "https://github.com/x64dbg/x64dbg/releases/download/2025.08.19/snapshot_2025-08-19_19-40.zip"
	"URL_Debuggers_WinDbgPreview" = "https://windbg.download.prss.microsoft.com/dbazure/prod/1-0-0/windbg.appinstaller"
	# Disassemblers & Decompilers
	"URL_Disassemblers_IDAFree" = "https://out7.hex-rays.com/files/idafree84_windows.exe"
	"URL_Disassemblers_BinaryNinja" = "https://cdn.binary.ninja/installers/binaryninja_free_win64.exe"
	"URL_Disassemblers_Ghidra" = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip"
	"URL_Disassemblers_Ghidra_BinExport_Compatible" = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip"
	"URL_Disassemblers_Cutter" = "https://github.com/rizinorg/cutter/releases/download/v2.4.1/Cutter-v2.4.1-Windows-x86_64.zip"
	"URL_Disassemblers_Radare2" = "https://github.com/radareorg/radare2/releases/download/6.0.4/r2blob-6.0.4-w64.zip"
	# Exploit Development
	"URL_ExploitDev_MonaCorelan" = "https://github.com/corelan/mona"
	"URL_ExploitDev_Monax64dbg" = "https://github.com/x64dbg/mona"
	"URL_ExploitDev_Monax64dbgpy" = "https://github.com/x64dbg/x64dbgpy/releases/download/8c0538a/x64dbgpy_8c0538a.zip"
	"URL_ExploitDev_Monax64dbgpylib" = "https://github.com/x64dbg/x64dbgpylib/archive/refs/heads/master.zip"
	"URL_ExploitDev_Monawindbglib" = "https://github.com/corelan/windbglib/archive/refs/heads/master.zip"
	"URL_ExploitDev_PykdWhl" = "https://files.pythonhosted.org/packages/12/2d/fabb94c8bdbfc1748da0f21867ed44eb12a6b016bfe87abe5872ba75d6a3/pykd-0.3.4.15-cp39-none-win_amd64.whl"
	"URL_ExploitDev_PykdDll" = "https://raw.githubusercontent.com/TheMalwareGuardian/WinDbg_Scripting/refs/heads/main/ScriptsHelloWorld/PyKd/pykd_ext_2.0.0.25/x64/pykd.dll"
	"URL_ExploitDev_ERCx64" = "https://github.com/Andy53/ERC.Xdbg/releases/download/64/ERC.Xdbg_64-2.0.3.zip"
	"URL_ExploitDev_ERCx32" = "https://github.com/Andy53/ERC.Xdbg/releases/download/32/ERC.Xdbg_32-2.0.3.zip"
	"URL_ExploitDev_RPPlusPlus" = "https://github.com/0vercl0k/rp/releases/download/v2.1.5/rp-win.zip"
	"URL_ExploitDev_Snowman64" = "https://github.com/x64dbg/snowman/releases/download/plugin-v1/snowman.dp64"
	"URL_ExploitDev_Snowman32" = "https://github.com/x64dbg/snowman/releases/download/plugin-v1/snowman.dp32"
	# Fuzzing
	"URL_Fuzzing_DinamoRIO" = "https://github.com/DynamoRIO/dynamorio/releases/download/release_11.3.0-1/DynamoRIO-Windows-11.3.0.zip"
	"URL_Fuzzing_WinAFL" = "https://github.com/googleprojectzero/winafl"
	# Binary Diffing
	"URL_BinaryDiffing_BinDiff" = "https://github.com/google/bindiff/releases/download/v8/bindiff8.msi"
	# Vulnerable Applications
	"URL_VulnApps_Vulnserver" = "https://github.com/stephenbradshaw/vulnserver/archive/refs/heads/master.zip"
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function Show-Menu {
	Clear-Host
	Write-Host "=========================================================================================================================="
	Write-Host "Overview:"
	Write-Host " - Script that automates the setup of a Debugging/Reversing/Exploiting environment on Windows"
	Write-Host "LinkedIn:"
	Write-Host " - $($ConfigURLs["URL_My_Linkedin"])"
	Write-Host "Github:"
	Write-Host " - $($ConfigURLs["URL_My_Repository"])"
	Write-Host " - $($ConfigURLs["URL_My_RepositoryBinaryExploitation"])"
	Write-Host " - $($ConfigURLs["URL_My_RepositoryThisOne"])"
	Write-Host "=========================================================================================================================="
	Write-Host ""
	Write-Host ""
	Write-Host "---------------------------------------------------------- MENU ----------------------------------------------------------"
	Write-Host " BINARY EXPLOITATION"
	Write-Host "    1a) Requirements    -   Git + Visual Studio 2019 Community + Windows SDK + Java JDK + Netcat"
	Write-Host "    1b) Requirements    -   Python 3 x64 + Venv + Python 2 x64"
	Write-Host "    2a) IDEs            -   Notepad++ + Visual Studio Code + Pycharm Community"
	Write-Host "    3a) Debuggers       -   Immunity Debugger + x64dbg + WinDbg Preview"
	Write-Host "    4a) Disassemblers   -   IDA Free + Binary Ninja + Ghidra + Cutter + Radare2"
	Write-Host "    5a) Exploit Dev     -   [Plugin Mona (Immunity Debugger)]"
	Write-Host "    5b) Exploit Dev     -   [Plugin Mona (x64dbg) + x64dbgpy + x64dbgpylib] + [Plugins ERC.Xdbg and Snowman (x64dbg)]"
	Write-Host "    5c) Exploit Dev     -   [Plugin Mona (Windbg) + windbglib + Pykd]"
	Write-Host "    5d) Exploit Dev     -   rp++"
	Write-Host "    6a) Fuzzing         -   DynamoRIO + WinAFL"
	Write-Host "    7a) Binary Diffing  -   BinDiff"
	Write-Host "    8a) Vuln Apps       -   Vulnserver"
	Write-Host ""
	Write-Host " PROGRAM TERMINATION"
	Write-Host "    Q) Exit"
	Write-Host "--------------------------------------------------------------------------------------------------------------------------"
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionRequirements1 {
	Write-Host "You have selected the option 'Requirements - Git + Visual Studio 2019 Community + Windows SDK + Java JDK'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempRequirementsBinaries = "TemporalRequirementsBinaries"
		$folderTempRequirementsBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempRequirementsBinaries
		if (-not (Test-Path -Path $folderTempRequirementsBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempRequirementsBinariesPath | Out-Null
		}

		# Git
		$install = Read-Host "Do you want to install Git? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Git" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Requirements_Git"], "$folderTempRequirementsBinariesPath\git.exe")
			$process = Start-Process -FilePath "$folderTempRequirementsBinariesPath\git.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Git" -ForegroundColor Yellow
		}

		# Visual Studio 2019 Community
		$install = Read-Host "Do you want to install Visual Studio 2019 Community? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Visual Studio 2019 Community:" -ForegroundColor Yellow
			Write-Host "  1. Under the 'Workloads' section -> 'Desktop & Mobile', select 'Desktop development with C++'" -ForegroundColor Yellow
			Write-Host "  2. Look for the 'Individual components' section located as the second option in the top left and select 'MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (latest)'" -ForegroundColor Yellow
			Write-Host "  3. Install Visual Studio" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Requirements_VisualStudio2019"], "$folderTempRequirementsBinariesPath\vs_Community.exe")
			$process = Start-Process -FilePath "$folderTempRequirementsBinariesPath\vs_Community.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Visual Studio 2019 Community" -ForegroundColor Yellow
		}

		# Windows SDK
		$install = Read-Host "Do you want to install Windows SDK? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Windows SDK" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Requirements_WindowsSDK"], "$folderTempRequirementsBinariesPath\winsdksetup.exe")
			$process = Start-Process -FilePath "$folderTempRequirementsBinariesPath\winsdksetup.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Windows SDK" -ForegroundColor Yellow
		}

		# Java JDK
		$install = Read-Host "Do you want to install Java JDK? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Java JDK" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Requirements_JavaJDK"], "$folderTempRequirementsBinariesPath\jdk.exe")
			$process = Start-Process -FilePath "$folderTempRequirementsBinariesPath\jdk.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Java JDK" -ForegroundColor Yellow
		}

		# Netcat
		$install = Read-Host "Do you want to install Netcat? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Netcat" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Requirements_Netcat"], "$folderTempRequirementsBinariesPath\nmap.exe")
			$process = Start-Process -FilePath "$folderTempRequirementsBinariesPath\nmap.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Netcat" -ForegroundColor Yellow
		}

		Remove-Item $folderTempRequirementsBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionRequirements2 {
	Write-Host "You have selected the option 'Requirements - Python 3 x64 + Venv + Python 2 x64'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempRequirementsBinaries = "TemporalRequirementsBinaries"
		$folderTempRequirementsBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempRequirementsBinaries
		if (-not (Test-Path -Path $folderTempRequirementsBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempRequirementsBinariesPath | Out-Null
		}

		# Python 3 x64
		$install = Read-Host "Do you want to install Python 3 x64? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Python 3 x64" -ForegroundColor Yellow
			Write-Host "  1. Check the option 'Add Python 3.X to PATH'." -ForegroundColor Yellow
			Write-Host "  2. Click 'Disable path length limit' at the end of the setup." -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Requirements_Python3x64"], "$folderTempRequirementsBinariesPath\python3x64.exe")
			$process = Start-Process -FilePath "$folderTempRequirementsBinariesPath\python3x64.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Python 3 x64" -ForegroundColor Yellow
		}

		<#
		# Create Python venv & install tools
		$createVenv = Read-Host "Do you want to create a Python virtual environment and install tools? (Y/N)"
		if ($createVenv -eq 'Y') {
			Write-Host "Creating Python virtual environment" -ForegroundColor Yellow

			# Locate python
			$pathPythonCmd = (Get-Command python).Path
			$pathVenv = Join-Path -Path $PSScriptRoot -ChildPath "VenvExploiting"
			& $pathPythonCmd -m venv $pathVenv 2>&1 | Out-Null

			# Venv
			$venvPython = Join-Path -Path $pathVenv -ChildPath "Scripts\python.exe"
			& $venvPython -m pip install --upgrade pip setuptools wheel 2>&1 | Out-Null

			# Packages
			$packages = @("capstone", "filebytes", "keystone-engine", "flawfinder", "ropper", "ROPgadget")
			foreach ($pkg in $packages) {
				& $venvPython -m pip install $pkg --no-warn-script-location
			}

			Write-Host "Created - Python virtual environment" -ForegroundColor Yellow
		}
		#>

		# Python 2 x64
		$install = Read-Host "Do you want to install Python 2 x64? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Python 2 x64" -ForegroundColor Yellow
			Write-Host "  1. Set the installation path manually to 'C:\Python27x64\'" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Requirements_Python2x64"], "$folderTempRequirementsBinariesPath\python2x64.msi")
			$process = Start-Process -FilePath "$folderTempRequirementsBinariesPath\python2x64.msi" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}

			# Environment variables
			Write-Host "Adding Python 2 x64 to PATH"
			$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
			$python27Path = "C:\Python27x64"
			$python27ScriptsPath = "C:\Python27x64\Scripts"
			[Environment]::SetEnvironmentVariable("Path", "$userPath;$python27Path;$python27ScriptsPath", "User")
			Write-Host "Paths $python27Path and $python27ScriptsPath added to the User Environment"

			Write-Host "Installed - Python 2 x64" -ForegroundColor Yellow
		}

		Remove-Item $folderTempRequirementsBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionIDEs {
	Write-Host "You have selected the option 'IDEs - Notepad++ + Visual Studio Code + Pycharm Community'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempIDEsBinaries = "TemporalIDEsBinaries"
		$folderTempIDEsBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempIDEsBinaries
		if (-not (Test-Path -Path $folderTempIDEsBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempIDEsBinariesPath | Out-Null
		}

		# Notepad++
		$install = Read-Host "Do you want to install Notepad++? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Notepad++" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_IDEs_Notepad"], "$folderTempIDEsBinariesPath\notepad.exe")
			$process = Start-Process -FilePath "$folderTempIDEsBinariesPath\notepad.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Notepad++" -ForegroundColor Yellow
		}

		# Visual Studio Code
		$install = Read-Host "Do you want to install Visual Studio Code? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Visual Studio Code" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_IDEs_VisualStudioCode"], "$folderTempIDEsBinariesPath\VSCodeUserSetup.exe")
			$process = Start-Process -FilePath "$folderTempIDEsBinariesPath\VSCodeUserSetup.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Visual Studio Code" -ForegroundColor Yellow
		}

		# Pycharm Community
		$install = Read-Host "Do you want to install Pycharm Community? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Pycharm Community" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_IDEs_PycharmCommunity"], "$folderTempIDEsBinariesPath\pycharm.exe")
			$process = Start-Process -FilePath "$folderTempIDEsBinariesPath\pycharm.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Pycharm Community" -ForegroundColor Yellow
		}

		Remove-Item $folderTempIDEsBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionDebuggers {
	Write-Host "You have selected the option 'Debuggers - Immunity Debugger + x64dbg + WinDbg Preview'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempDebuggersBinaries = "TemporalDebuggersBinaries"
		$folderTempDebuggersBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempDebuggersBinaries
		if (-not (Test-Path -Path $folderTempDebuggersBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempDebuggersBinariesPath | Out-Null
		}

		# Debuggers folder
		$pathRootDebuggers = Join-Path -Path $PSScriptRoot -ChildPath "Debuggers"
		if (-not (Test-Path -Path $pathRootDebuggers)) {
			New-Item -ItemType Directory -Path $pathRootDebuggers | Out-Null
		}

		# Immunity Debugger
		$install = Read-Host "Do you want to install Immunity Debugger? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Immunity Debugger" -ForegroundColor Yellow
			Write-Host "  1. Install Python 2 x86 included with the Immunity Debugger setup." -ForegroundColor Yellow

			# Download
			$pathImmunityDebuggerZipFile = Join-Path $folderTempDebuggersBinariesPath "ImmunityDebuggerSetup.zip"
			Write-Host "Downloading Immunity Debugger"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Debuggers_ImmunityDebugger"], $pathImmunityDebuggerZipFile)

			# ZIP
			$pathImmunityDebuggerZipExtract = Join-Path $folderTempDebuggersBinariesPath "ImmunityDebuggerExtracted"
			New-Item -ItemType Directory -Path $pathImmunityDebuggerZipExtract | Out-Null
			Write-Host "Extracting ZIP file"
			Expand-Archive -Path $pathImmunityDebuggerZipFile -DestinationPath $pathImmunityDebuggerZipExtract -Force

			# Installer
			$exe = Get-ChildItem -Path $pathImmunityDebuggerZipExtract -Recurse -Include *.exe -File -ErrorAction SilentlyContinue | Select-Object -First 1

			$pathImmunityDebuggerInstaller = $exe.FullName
			Write-Host "Starting installer"
			$process = Start-Process -FilePath $pathImmunityDebuggerInstaller -PassThru
			$process.WaitForExit()
			while ($true) {
				$completed = Read-Host "Installation completed? (Y/N)"
				if ($completed -eq "Y") {
					break
				}
			}

			Write-Host "Installed - Immunity Debugger" -ForegroundColor Yellow
		}

		# x64dbg
		$install = Read-Host "Do you want to download x64dbg? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Downloading x64dbg" -ForegroundColor Yellow

			# ZIP
			$pathx64dbgZipFile = Join-Path $folderTempDebuggersBinariesPath "x64dbg_snapshot.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Debuggers_x64dbg"], $pathx64dbgZipFile)

			$pathx64dbg = Join-Path $pathRootDebuggers "x64dbg"
			if (Test-Path $pathx64dbg) {
				Remove-Item $pathx64dbg -Recurse -Force
			}
			New-Item -ItemType Directory -Path $pathx64dbg | Out-Null
			Expand-Archive -Path $pathx64dbgZipFile -DestinationPath $pathx64dbg -Force

			Write-Host "Downloaded - x64dbg" -ForegroundColor Yellow
		}

		# WinDbg
		$install = Read-Host "Do you want to install WinDbg? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing WinDbg" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Debuggers_WinDbgPreview"], "$folderTempDebuggersBinariesPath\windbg.appinstaller")
			Add-AppxPackage -AppInstallerFile "$folderTempDebuggersBinariesPath\windbg.appinstaller"
			Write-Host "Installed - WinDbg" -ForegroundColor Yellow
		}

		Remove-Item $folderTempDebuggersBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionDisassemblers {
	Write-Host "You have selected the option 'Disassemblers - IDA Free + Binary Ninja + Ghidra + Cutter + Radare2'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempDisassemblersBinaries = "TemporalDisassemblersBinaries"
		$folderTempDisassemblersBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempDisassemblersBinaries
		if (-not (Test-Path -Path $folderTempDisassemblersBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempDisassemblersBinariesPath | Out-Null
		}

		# Disassemblers
		$pathRootDisassemblers = Join-Path -Path $PSScriptRoot -ChildPath "Disassemblers"
		if (-not (Test-Path -Path $pathRootDisassemblers)) {
			New-Item -ItemType Directory -Path $pathRootDisassemblers | Out-Null
		}

		# IDA Free
		$install = Read-Host "Do you want to install IDA Free? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing IDA Free" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Disassemblers_IDAFree"], "$folderTempDisassemblersBinariesPath\idafree_windows.exe")
			$process = Start-Process -FilePath "$folderTempDisassemblersBinariesPath\idafree_windows.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - IDA Free" -ForegroundColor Yellow
		}

		# Binary Ninja
		$install = Read-Host "Do you want to install Binary Ninja? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing Binary Ninja" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Disassemblers_BinaryNinja"], "$folderTempDisassemblersBinariesPath\binaryninja.exe")
			$process = Start-Process -FilePath "$folderTempDisassemblersBinariesPath\binaryninja.exe" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - Binary Ninja" -ForegroundColor Yellow
		}

		# Ghidra
		$install = Read-Host "Do you want to download Ghidra? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Downloading Ghidra" -ForegroundColor Yellow

			# ZIP
			$pathGhidraZipFile = Join-Path $folderTempDisassemblersBinariesPath "ghidra.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Disassemblers_Ghidra"], $pathGhidraZipFile)
			Expand-Archive -Path $pathGhidraZipFile -DestinationPath $pathRootDisassemblers -Force

			# Folder
			$pathGhidraZipExtract = Get-ChildItem -Path $pathRootDisassemblers -Directory | Where-Object { $_.Name -like "ghidra_*" } | Select-Object -First 1
			$pathGhidraNewName = "Ghidra"
			$pathGhidraNewPath = Join-Path $pathRootDisassemblers $pathGhidraNewName
			if (Test-Path $pathGhidraNewPath) {
				Remove-Item -Recurse -Force $pathGhidraNewPath
			}
			Rename-Item -Path $pathGhidraZipExtract.FullName -NewName $pathGhidraNewName

			Write-Host "Downloaded - Ghidra" -ForegroundColor Yellow
		}

		# Cutter
		$install = Read-Host "Do you want to download Cutter? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Downloading Cutter" -ForegroundColor Yellow

			# ZIP
			$pathCutterZipFile = Join-Path $folderTempDisassemblersBinariesPath "cutter.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Disassemblers_Cutter"], $pathCutterZipFile)
			Expand-Archive -Path $pathCutterZipFile -DestinationPath $pathRootDisassemblers -Force

			# Folder
			$pathCutterZipExtract = Get-ChildItem -Path $pathRootDisassemblers -Directory | Where-Object { $_.Name -like "Cutter*" } | Select-Object -First 1
			$pathCutterNewName = "Cutter"
			$pathCutterNewPath = Join-Path $pathRootDisassemblers $pathCutterNewName
			if (Test-Path $pathCutterNewPath) {
				Remove-Item -Recurse -Force $pathCutterNewPath
			}
			Rename-Item -Path $pathCutterZipExtract.FullName -NewName $pathCutterNewName

			Write-Host "Downloaded - Cutter" -ForegroundColor Yellow
		}

		# Radare2
		$install = Read-Host "Do you want to download Radare2? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Downloading Radare2" -ForegroundColor Yellow

			# ZIP
			$pathRadareZipFile = Join-Path $folderTempDisassemblersBinariesPath "radare2.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Disassemblers_Radare2"], $pathRadareZipFile)

			# Folder
			$pathRadare = Join-Path $pathRootDisassemblers "Radare2"
			if (Test-Path $pathRadare) {
				Remove-Item $pathRadare -Recurse -Force
			}
			New-Item -ItemType Directory -Path $pathRadare | Out-Null
			Expand-Archive -Path $pathRadareZipFile -DestinationPath $pathRadare -Force

			# Environment variables
			Write-Host "Adding Radare2 to PATH"
			$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
			[System.Environment]::SetEnvironmentVariable("Path", "$userPath;$pathRadare", "User")
			Write-Host "Path $pathRadare added to the User Environment"

			Write-Host "Downloaded - Radare2" -ForegroundColor Yellow
		}

		Remove-Item $folderTempDisassemblersBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionExploitDevMonaImmunity {
	Write-Host "You have selected the option 'Exploit Development - [Plugin Mona (Immunity Debugger)]'" -ForegroundColor Green
	$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	if (-not $isAdmin) {
		Write-Warning "Administrator privileges required. The script will relaunch elevated."
		Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
		return
	}
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Exploit Development
		$pathRootExploitDev = Join-Path -Path $PSScriptRoot -ChildPath "Exploit Development"
		if (-not (Test-Path -Path $pathRootExploitDev)) {
			New-Item -ItemType Directory -Path $pathRootExploitDev | Out-Null
		}

		# Mona Corelan
		Write-Host "Setting up Mona" -ForegroundColor Yellow
		Write-Host "  1. Open Immunity Debugger as Administrator." -ForegroundColor Yellow
		Write-Host "  2. Verify Mona was installed by typing '!mona help' in the bottom input box." -ForegroundColor Yellow

		# Clone
		$pathMona = Join-Path -Path $pathRootExploitDev -ChildPath "MonaCorelan"
		if (-not (Test-Path $pathMona)) {
			git clone $ConfigURLs["URL_ExploitDev_MonaCorelan"] $pathMona
		}

		# File mona.py
		$pathMonaPythonFile = Join-Path -Path $pathMona -ChildPath "mona.py"
		$pathImmunityDebuggerPyCommands = "C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands"
		Copy-Item -Path $pathMonaPythonFile -Destination $pathImmunityDebuggerPyCommands

		Write-Host "Configured - Mona" -ForegroundColor Yellow
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionExploitDevMonax64dbgERCx64dbg {
	Write-Host "You have selected the option 'Exploit Development - [Plugin Mona (x64dbg) + x64dbgpy + x64dbgpylib] + [Plugins ERC.Xdbg and Snowman (x64dbg)]'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempExploitDevBinaries = "TemporalExploitDevBinaries"
		$folderTempExploitDevBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempExploitDevBinaries
		if (-not (Test-Path -Path $folderTempExploitDevBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempExploitDevBinariesPath | Out-Null
		}

		# Exploit Development
		$pathRootExploitDev = Join-Path -Path $PSScriptRoot -ChildPath "Exploit Development"
		if (-not (Test-Path -Path $pathRootExploitDev)) {
			New-Item -ItemType Directory -Path $pathRootExploitDev | Out-Null
		}

		# x64dbg
		$pathx64dbgRelease = Join-Path $PSScriptRoot "Debuggers\x64dbg\release"
		$pathx64dbgReleasePluginx64 = Join-Path $pathx64dbgRelease "x64\plugins"
		$pathx64dbgReleasePluginx32 = Join-Path $pathx64dbgRelease "x32\plugins"

		# Mona x64dbg
		$install = Read-Host "Do you want to configure Mona? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Setting up Mona" -ForegroundColor Yellow
			Write-Host "  1. Open x64dbg or x32dbg." -ForegroundColor Yellow
			Write-Host "  2. Change the command mode selector to 'Python' and in the bottom input box run 'mona.mona(`"help`")' to verify initialization." -ForegroundColor Yellow
			Write-Host "     2.1. If you get NameError: name 'mona' is not defined, open the 'clean_mona.py' content and paste it into the input box then retry." -ForegroundColor Yellow

			# Clone
			$monaFolder = Join-Path -Path $pathRootExploitDev -ChildPath "Monax64dbg"
			if (-not (Test-Path $monaFolder)) {
				git clone $ConfigURLs["URL_ExploitDev_Monax64dbg"] $monaFolder
			}

			# Package x64dbgpy
			$pathPackagex64dbgpyZipFile = Join-Path $folderTempExploitDevBinariesPath "x64dbgpy.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_Monax64dbgpy"], $pathPackagex64dbgpyZipFile)

			$pathPackagex64dbgpyZipExtract = Join-Path $folderTempExploitDevBinariesPath "x64dbgpy_extracted"
			Expand-Archive -Path $pathPackagex64dbgpyZipFile -DestinationPath $pathPackagex64dbgpyZipExtract -Force

			$pathPackagex64dbgpyZipExtractPluginsx64 = Join-Path $pathPackagex64dbgpyZipExtract "x64\plugins"
			$pathPackagex64dbgpyZipExtractPluginsx32 = Join-Path $pathPackagex64dbgpyZipExtract "x32\plugins"

			Copy-Item -Path $pathPackagex64dbgpyZipExtractPluginsx64 -Destination $pathx64dbgReleasePluginx64 -Recurse
			Copy-Item -Path $pathPackagex64dbgpyZipExtractPluginsx32 -Destination $pathx64dbgReleasePluginx32 -Recurse

			# Package x64dbgpylib
			$pathPackagex64dbgpylibZipFile = Join-Path $folderTempExploitDevBinariesPath "x64dbgpylib.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_Monax64dbgpylib"], $pathPackagex64dbgpylibZipFile)

			$pathPackagex64dbgpylibZipExtract = Join-Path $folderTempExploitDevBinariesPath "x64dbgpylib_extracted"
			Expand-Archive -Path $pathPackagex64dbgpylibZipFile -DestinationPath $pathPackagex64dbgpylibZipExtract -Force

			$pathPackagex64dbgpylibZipExtractPythonFiles = Get-ChildItem -Path $pathPackagex64dbgpylibZipExtract -Recurse -Filter *.py -File

			foreach ($file in $pathPackagex64dbgpylibZipExtractPythonFiles) {
				Copy-Item -Path $file.FullName -Destination (Join-Path $pathx64dbgReleasePluginx64 "x64dbgpy") -Recurse
				Copy-Item -Path $file.FullName -Destination (Join-Path $pathx64dbgReleasePluginx32 "x64dbgpy") -Recurse
			}

			# File mona.py
			$pathMonaPythonFile = Get-ChildItem -Path $monaFolder -Recurse -Filter mona.py -File | Select-Object -First 1
			Copy-Item -Path $pathMonaPythonFile.FullName -Destination (Join-Path $pathx64dbgReleasePluginx64 "x64dbgpy") -Recurse
			Copy-Item -Path $pathMonaPythonFile.FullName -Destination (Join-Path $pathx64dbgReleasePluginx32 "x64dbgpy") -Recurse

			# File clean_mona.py
			$pathMonaCleanPythonFile = Get-ChildItem -Path $monaFolder -Recurse -Filter clean_mona.py -File | Select-Object -First 1
			Copy-Item -Path $pathMonaCleanPythonFile.FullName -Destination (Join-Path $pathx64dbgReleasePluginx64 "x64dbgpy\x64dbgpy\autorun") -Recurse
			Copy-Item -Path $pathMonaCleanPythonFile.FullName -Destination (Join-Path $pathx64dbgReleasePluginx32 "x64dbgpy\x64dbgpy\autorun") -Recurse

			Write-Host "Configured - Mona" -ForegroundColor Yellow
		}

		# ERC.Xdbg
		$install = Read-Host "Do you want to configure ERC.Xdbg? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Setting up ERC.Xdbg" -ForegroundColor Yellow
			Write-Host "  1. Open x64dbg or x32dbg." -ForegroundColor Yellow
			Write-Host "  2. Change the command mode selector to 'Python' and in the bottom input box run 'ERC --Help' to verify initialization." -ForegroundColor Yellow

			# ERC x64
			$pathPackageERCx64ZipFile = Join-Path $folderTempExploitDevBinariesPath "ERC_x64.zip"
			$pathPackageERCx64ZipExtract = Join-Path $folderTempExploitDevBinariesPath "ERC_x64_extracted"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_ERCx64"], $pathPackageERCx64ZipFile)
			Expand-Archive -Path $pathPackageERCx64ZipFile -DestinationPath $pathPackageERCx64ZipExtract -Force
			Get-ChildItem -Path $pathPackageERCx64ZipExtract -Force | ForEach-Object {
				Copy-Item -Path $_.FullName -Destination $pathx64dbgReleasePluginx64 -Recurse -Force
			}

			# ERC x32
			$pathPackageERCx32ZipFile = Join-Path $folderTempExploitDevBinariesPath "ERC_x32.zip"
			$pathPackageERCx32ZipExtract = Join-Path $folderTempExploitDevBinariesPath "ERC_x32_extracted"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_ERCx32"], $pathPackageERCx32ZipFile)
			Expand-Archive -Path $pathPackageERCx32ZipFile -DestinationPath $pathPackageERCx32ZipExtract -Force
			Get-ChildItem -Path $pathPackageERCx32ZipExtract -Force | ForEach-Object {
				Copy-Item -Path $_.FullName -Destination $pathx64dbgReleasePluginx32 -Recurse -Force
			}

			Write-Host "Configured - ERC.Xdbg" -ForegroundColor Yellow
		}

		# Snowman
		$install = Read-Host "Do you want to configure Snowman? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Setting up Snowman plugin" -ForegroundColor Yellow

			# Dp files
			$pathPackageSnowmanDp64 = Join-Path $pathx64dbgReleasePluginx64 "snowman.dp64"
			$pathPackageSnowmanDp32 = Join-Path $pathx64dbgReleasePluginx32 "snowman.dp32"

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_Snowman64"], $pathPackageSnowmanDp64)
			$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_Snowman32"], $pathPackageSnowmanDp32)

			Write-Host "Configured - Snowman" -ForegroundColor Yellow
		}

		Remove-Item $folderTempExploitDevBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionExploitDevMonaWinDbg {
	Write-Host "You have selected the option 'Exploit Development - [Plugin Mona (Windbg) + windbglib + Pykd]'" -ForegroundColor Green
	$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	if (-not $isAdmin) {
		Write-Warning "Administrator privileges required. The script will relaunch elevated."
		Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
		return
	}
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempExploitDevBinaries = "TemporalExploitDevBinaries"
		$folderTempExploitDevBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempExploitDevBinaries
		if (-not (Test-Path -Path $folderTempExploitDevBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempExploitDevBinariesPath | Out-Null
		}

		# Exploit Development
		$exploitDevRoot = Join-Path -Path $PSScriptRoot -ChildPath "Exploit Development"
		if (-not (Test-Path -Path $exploitDevRoot)) {
			New-Item -ItemType Directory -Path $exploitDevRoot | Out-Null
		}

		# WinDbg
		$pathRootWindbgX64 = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
		$pathRootWindbgX32 = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86"

		# Mona Corelan
		Write-Host "Setting up Mona" -ForegroundColor Yellow
		Write-Host "  1. Open WinDbg , attach to a running x86 process, and at the kd> command line run the commands 'kd> .load pykd.pyd' and 'kd> !py mona' to start Mona." -ForegroundColor Yellow
		Write-Host "  2. Open WinDbg , attach to a running x64 process, and at the kd> command line run the commands 'kd> .load pykd' and 'kd> !py -2 mona' to start Mona." -ForegroundColor Yellow

		# Clone
		$monaFolder = Join-Path -Path $exploitDevRoot -ChildPath "MonaCorelan"
		if (-not (Test-Path $monaFolder)) {
			git clone $ConfigURLs["URL_ExploitDev_MonaCorelan"] $monaFolder
		}

		# Package windbglib
		$pathPackagewindbglibZipFile = Join-Path $folderTempExploitDevBinariesPath "windbglib.zip"
		$webClient = New-Object System.Net.WebClient
		$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_Monawindbglib"], $pathPackagewindbglibZipFile)

		$pathPackagewindbglibZipExtract = Join-Path $folderTempExploitDevBinariesPath "windbglib_extracted"
		Expand-Archive -Path $pathPackagewindbglibZipFile -DestinationPath $pathPackagewindbglibZipExtract -Force

		# File pykd.zip
		$pathPackagewindbgliPykdZipFile = Get-ChildItem -Path $pathPackagewindbglibZipExtract -Recurse -Filter "pykd.zip" -File | Select-Object -First 1
		$pathPackagewindbgliPykdZipExtract = Join-Path $folderTempExploitDevBinariesPath "windbglib_pykd_extracted"
		Expand-Archive -Path $pathPackagewindbgliPykdZipFile.FullName -DestinationPath $pathPackagewindbgliPykdZipExtract -Force

		# File pykd.pyd
		$pathPykdPydFile = Get-ChildItem -Path $pathPackagewindbgliPykdZipExtract -Recurse -Filter "pykd.pyd" -File | Select-Object -First 1
		Copy-Item -Path $pathPykdPydFile.FullName -Destination (Join-Path $pathRootWindbgX32 "winext") -Force

		# File vcredist.exe
		$pathvcredistFile = Get-ChildItem -Path $pathPackagewindbgliPykdZipExtract -Recurse -Filter "vcredist*.exe" -File | Select-Object -First 1
		$process = Start-Process -FilePath $pathvcredistFile.FullName -PassThru
		$process.WaitForExit()
		while ($true) {
			$response = Read-Host "Installation completed? (Y/N)"
			if ($response -eq "Y") {
				break
			}
		}

		# Register msdia90.dll
		$pathmsdiaFile = "C:\Program Files (x86)\Common Files\Microsoft Shared\VC\msdia90.dll"
		$process = Start-Process -FilePath "regsvr32.exe" -ArgumentList "`"$pathmsdiaFile`"" -PassThru
		$process.WaitForExit()
		while ($true) {
			$response = Read-Host "Registration completed? (Y/N)"
			if ($response -eq "Y") {
				break
			}
		}

		# File pykd.whl
		$webClient = New-Object System.Net.WebClient
		$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_PykdWhl"], (Join-Path $folderTempExploitDevBinariesPath "pykd.whl"))
		Copy-Item -Path (Join-Path $folderTempExploitDevBinariesPath "pykd.whl") -Destination (Join-Path $pathRootWindbgX64 "winext")

		# File pykd.dll
		$webClient = New-Object System.Net.WebClient
		$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_PykdDll"], (Join-Path $folderTempExploitDevBinariesPath "pykd.dll"))
		Copy-Item -Path (Join-Path $folderTempExploitDevBinariesPath "pykd.dll") -Destination (Join-Path $pathRootWindbgX64 "winext")

		# Import pykd
		$pathPythonx64ExeFile = "C:\Python27x64\python.exe"
		$process = Start-Process -FilePath $pathPythonx64ExeFile -ArgumentList "-m", "pip", "install", "pykd" -WorkingDirectory "C:\Python27x64" -PassThru
		$process.WaitForExit()
		while ($true) {
			$response = Read-Host "Installation completed? (Y/N)"
			if ($response -eq "Y") {
				break
			}
		}

		# File windbglib.py
		$pathwindbglibPythonFile = Get-ChildItem -Path $pathPackagewindbglibZipExtract -Recurse -Filter "windbglib.py" -File | Select-Object -First 1
		Copy-Item -Path $pathwindbglibPythonFile.FullName -Destination $pathRootWindbgX64
		Copy-Item -Path $pathwindbglibPythonFile.FullName -Destination $pathRootWindbgX32

		# File mona.py
		$pathMonaPythonFile = Join-Path -Path $monaFolder -ChildPath "mona.py"
		Copy-Item -Path $pathMonaPythonFile -Destination $pathRootWindbgX64
		Copy-Item -Path $pathMonaPythonFile -Destination $pathRootWindbgX32

		Write-Host "Configured - Mona" -ForegroundColor Yellow

		Remove-Item $folderTempExploitDevBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionExploitDevROP {
	Write-Host "You have selected the option 'Exploit Development - rp++'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempExploitDevBinaries = "TemporalExploitDevBinaries"
		$folderTempExploitDevBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempExploitDevBinaries
		if (-not (Test-Path -Path $folderTempExploitDevBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempExploitDevBinariesPath | Out-Null
		}

		# Exploit Development
		$exploitDevRoot = Join-Path -Path $PSScriptRoot -ChildPath "Exploit Development"
		if (-not (Test-Path -Path $exploitDevRoot)) {
			New-Item -ItemType Directory -Path $exploitDevRoot | Out-Null
		}

		# rp++
		$install = Read-Host "Do you want to download rp++? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Downloading rp++" -ForegroundColor Yellow

			# ZIP
			$pathRPPlusPlusZipFile = Join-Path $folderTempExploitDevBinariesPath "rp_plus_plus.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_ExploitDev_RPPlusPlus"], $pathRPPlusPlusZipFile)

			# Folder
			$pathRPPlusPlus = Join-Path $exploitDevRoot "ROPGadgetFinder"
			if (Test-Path $pathRPPlusPlus) {
				Remove-Item $pathRPPlusPlus -Recurse -Force
			}
			New-Item -ItemType Directory -Path $pathRPPlusPlus | Out-Null
			Expand-Archive -Path $pathRPPlusPlusZipFile -DestinationPath $pathRPPlusPlus -Force

			# Environment variables
			Write-Host "Adding rp++ to PATH"
			$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
			[System.Environment]::SetEnvironmentVariable("Path", "$userPath;$pathRPPlusPlus", "User")
			Write-Host "Path $pathRPPlusPlus added to the User Environment"

			Write-Host "Downloaded - rp++" -ForegroundColor Yellow
		}

		Remove-Item $folderTempExploitDevBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionFuzzing {
	Write-Host "You have selected the option 'Fuzzing - DynamoRIO + WinAFL'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempFuzzingBinaries = "TemporalFuzzingBinaries"
		$folderTempFuzzingBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempFuzzingBinaries
		if (-not (Test-Path -Path $folderTempFuzzingBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempFuzzingBinariesPath | Out-Null
		}

		# Fuzzing
		$pathRootFuzzing = Join-Path -Path $PSScriptRoot -ChildPath "Fuzzing"
		if (-not (Test-Path -Path $pathRootFuzzing)) {
			New-Item -ItemType Directory -Path $pathRootFuzzing | Out-Null
		}

		# DynamoRIO
		$install = Read-Host "Do you want to download DynamoRIO? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Downloading DynamoRIO" -ForegroundColor Yellow

			# ZIP
			$pathDynamoZipFile = Join-Path $folderTempFuzzingBinariesPath "dynamorio.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_Fuzzing_DinamoRIO"], $pathDynamoZipFile)
			Expand-Archive -Path $pathDynamoZipFile -DestinationPath $pathRootFuzzing -Force

			$pathDynamoExtract = Get-ChildItem -Path $pathRootFuzzing -Directory | Where-Object { $_.Name -like "DynamoRIO*" } | Select-Object -First 1
			$pathDynamoNewName = "DynamoRIO"
			$pathDynamoNewPath = Join-Path $pathRootFuzzing $pathDynamoNewName
			if (Test-Path $pathDynamoNewPath) {
				Remove-Item -Recurse -Force $pathDynamoNewPath
			}
			Rename-Item -Path $pathDynamoExtract.FullName -NewName $pathDynamoNewName

			Write-Host "Downloaded - DynamoRIO" -ForegroundColor Yellow
		}

		# WinAFL
		$install = Read-Host "Do you want to build WinAFL? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Building WinAFL" -ForegroundColor Yellow

			# Clone
			$pathWinAFL = Join-Path $pathRootFuzzing "WinAFL"
			if (-not (Test-Path $pathWinAFL)) {
				git clone $ConfigURLs["URL_Fuzzing_WinAFL"] $pathWinAFL
			}

			# Submodules
			Set-Location $pathWinAFL
			git submodule update --init --recursive
			Set-Location $PSScriptRoot

			# Developer Command Prompt for VS2019 Community
			$vsDevCmd = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"

			# 64
			$pathWinAFLBuild64 = Join-Path $pathWinAFL "build64"
			if (-not (Test-Path $pathWinAFLBuild64)) {
				New-Item -ItemType Directory -Path $pathWinAFLBuild64 | Out-Null
			}

			# 32
			$pathWinAFLBuild32 = Join-Path $pathWinAFL "build32"
			if (-not (Test-Path $pathWinAFLBuild32)) {
				New-Item -ItemType Directory -Path $pathWinAFLBuild32 | Out-Null
			}

			# Build
			$pathDynamoCmake = Join-Path $pathRootFuzzing "DynamoRIO\cmake"
			$cmakeCmd64 = "cmake -G `"Visual Studio 16 2019`" -A x64 .. -DDynamoRIO_DIR=`"$pathDynamoCmake`" -DTINYINST=1 -DINTELPT=1"
			$cmakeCmd32 = "cmake -G `"Visual Studio 16 2019`" -A Win32 .. -DDynamoRIO_DIR=`"$pathDynamoCmake`" -DTINYINST=1 -DINTELPT=1"
			$buildCmd = "cmake --build . --config Release"
			cmd /c "`"$vsDevCmd`" && cd /d `"$pathWinAFLBuild64`" && $cmakeCmd64 && $buildCmd"
			cmd /c "`"$vsDevCmd`" && cd /d `"$pathWinAFLBuild32`" && $cmakeCmd32 && $buildCmd"

			<#
			# Environment variables
			$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
			$pathWinAFLBin64 = Join-Path $pathWinAFLBuild64 "bin\Release"
			$pathWinAFLBin32 = Join-Path $pathWinAFLBuild32 "bin\Release"
			[System.Environment]::SetEnvironmentVariable("Path", "$userPath;$pathWinAFLBin64;$pathWinAFLBin32", "User")
			Write-Host "Paths $pathWinAFLBin64 and $pathWinAFLBin32 added to the User Environment"
			#>

			Write-Host "Built - WinAFL" -ForegroundColor Yellow
		}

		Remove-Item $folderTempFuzzingBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionBinaryDiffing {
	Write-Host "You have selected the option 'Binary Diffing - BinDiff'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempBinaryDiffing = "TemporalBinaryDiffingBinaries"
		$folderTempBinaryDiffingPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempBinaryDiffing
		if (-not (Test-Path -Path $folderTempBinaryDiffingPath)) {
			New-Item -ItemType Directory -Path $folderTempBinaryDiffingPath | Out-Null
		}

		# BinDiff
		$install = Read-Host "Do you want to install BinDiff? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Installing BinDiff" -ForegroundColor Yellow

			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_BinaryDiffing_BinDiff"], "$folderTempBinaryDiffingPath\bindiff.msi")
			$process = Start-Process -FilePath "$folderTempBinaryDiffingPath\bindiff.msi" -PassThru
			$process.WaitForExit()
			while ($true) {
				$response = Read-Host "Installation completed? (Y/N)"
				if ($response -eq "Y") {
					break
				}
			}
			Write-Host "Installed - BinDiff" -ForegroundColor Yellow
		}

		Remove-Item $folderTempBinaryDiffingPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
function OptionVulnApps {
	Write-Host "You have selected the option 'Vulnerable Applications - Vulnserver'" -ForegroundColor Green
	$response = Read-Host "Do you want to proceed? (Press 'Y')"
	if ($response -eq "Y") {

		# Temp folder
		$folderTempVulnAppsBinaries = "TemporalVulnsAppsBinaries"
		$folderTempVulnAppsBinariesPath = Join-Path -Path $PSScriptRoot -ChildPath $folderTempVulnAppsBinaries
		if (-not (Test-Path -Path $folderTempVulnAppsBinariesPath)) {
			New-Item -ItemType Directory -Path $folderTempVulnAppsBinariesPath | Out-Null
		}

		# Vulnerable Applications
		$pathRootVulnApps = Join-Path -Path $PSScriptRoot -ChildPath "Vulnerable Applications"
		if (-not (Test-Path -Path $pathRootVulnApps)) {
			New-Item -ItemType Directory -Path $pathRootVulnApps | Out-Null
		}

		# Vulnserver
		$install = Read-Host "Do you want to download Vulnserver? (Y/N)"
		if ($install -eq "Y") {
			Write-Host "Downloading Vulnserver" -ForegroundColor Yellow

			# ZIP
			$pathVulnserverZipFile = Join-Path $folderTempVulnAppsBinariesPath "vulnserver.zip"
			$webClient = New-Object System.Net.WebClient
			$webClient.DownloadFile($ConfigURLs["URL_VulnApps_Vulnserver"], $pathVulnserverZipFile)

			$pathVulnserverZipExtract = Join-Path $folderTempVulnAppsBinariesPath "vulnserver_extracted"
			New-Item -ItemType Directory -Path $pathVulnserverZipExtract | Out-Null
			Expand-Archive -Path $pathVulnserverZipFile -DestinationPath $pathVulnserverZipExtract -Force

			$vulnserverFolder = Join-Path $pathRootVulnApps "Vulnserver"
			New-Item -ItemType Directory -Path $vulnserverFolder | Out-Null

			$pathVulnserverZipExtractMasterFolder = Get-ChildItem -Path $pathVulnserverZipExtract -Directory | Select-Object -First 1
			Get-ChildItem -Path $pathVulnserverZipExtractMasterFolder.FullName -Force | ForEach-Object {
				Move-Item -Path $_.FullName -Destination $vulnserverFolder -Force
			}

			Write-Host "Downloaded - Vulnserver" -ForegroundColor Yellow
		}

		Remove-Item $folderTempVulnAppsBinariesPath -Recurse
	}
}



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
do {
	Show-Menu
	$choice = Read-Host "Choose an option"
	switch ($choice) {
		'1a' { OptionRequirements1 }
		'1b' { OptionRequirements2 }
		'2a' { OptionIDEs }
		'3a' { OptionDebuggers }
		'4a' { OptionDisassemblers }
		'5a' { OptionExploitDevMonaImmunity }
		'5b' { OptionExploitDevMonax64dbgERCx64dbg }
		'5c' { OptionExploitDevMonaWindbg }
		'5d' { OptionExploitDevROP }
		'6a' { OptionFuzzing }
		'7a' { OptionBinaryDiffing }
		'8a' { OptionVulnApps }
		'Q' { break }
		default { Write-Host "Invalid option. Please choose again." }
	}
	Write-Host "Press any key to continue..."
	$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} while ($choice -ne 'Q')



# ---------------------------------------------------------------------------------------------------------------------------------------------------------
