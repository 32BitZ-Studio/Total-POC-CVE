# CVE-2021-1675 / CVE-2021-34527

Two mini Script to check if the PrintSpooler Serivce is running within the Forest.

CVE-2021-1675:

https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-1675

CVE-2021-34527 aka PrintNightmare

https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527

## Scripts

Detect running Printer Spooler Service on DCs:

https://github.com/DenizSe/CVE-2021-1675/blob/main/Get-PrinterSpoolerState.ps1

Detect running Printer Spooler Service on Machines within OU:

https://github.com/DenizSe/CVE-2021-1675/blob/main/Get-PrinterSpoolerStateOU.ps1

# Official Guidance (Taken from CVE-2021-34527

## Workarounds
Determine if the Print Spooler service is running (run as a Domain Admin)

Run the following as a Domain Admin:

Get-Service -Name Spooler

If the Print Spooler is running or if the service is not set to disabled, select one of the following options to either disable the Print Spooler service, or to Disable inbound remote printing through Group Policy:

### Option 1 - Disable the Print Spooler service

If disabling the Print Spooler service is appropriate for your enterprise, use the following PowerShell commands:

Stop-Service -Name Spooler -Force

Set-Service -Name Spooler -StartupType Disabled

Impact of workaround Disabling the Print Spooler service disables the ability to print both locally and remotely.

### Option 2 - Disable inbound remote printing through Group Policy

You can also configure the settings via Group Policy as follows:

Computer Configuration / Administrative Templates / Printers

Disable the “Allow Print Spooler to accept client connections:” policy to block remote attacks.

Impact of workaround This policy will block the remote attack vector by preventing inbound remote printing operations. The system will no longer function as a print server, but local printing to a directly attached device will still be possible.

For more information see: Use Group Policy settings to control printers.
