# VirtualLockSensorLPE
## Description

Local privilege escalation PoC exploit for CVE-2025-0886 that targets Elliptic Virtual Lock Sensor version 3.1.60531.2 running on Windows, which is installed by default on certain Lenovo laptop models. Allows execution of a payload in the context of `SYSTEM` from a regular user context by changing the permissions on a registry key.

Official advisory from Lenovo: https://support.lenovo.com/us/en/product_security/LEN-182738

Please read the [Notes](#notes) before using it.

## How to Build

1. Clone the repository with `git clone --recursive`.
2. Build the VirtualLockSensorLPE solution.

## How to Use

`VirtualLockSensorLPE.exe COMMAND`

### Example

`VirtualLockSensorLPE.exe "cmd /c echo test > C:\Windows\System32\poc.txt"`

![Screenshot](poc.png)

## Technical Details

Vulnerable versions of Elliptic Virtual Lock Sensor use the following registry keys where `Everyone` has `Full Control`:
- `HKLM\SOFTWARE\Elliptic Labs\Virtual Lock Sensor\UserSettings\OnBattery`
- `HKLM\SOFTWARE\Elliptic Labs\Virtual Lock Sensor\UserSettings\PluggedIn`

Regular users can initiate a reinstall of the software. If a subkey with "container inherit" enabled is created under one of the registry keys listed above, and a registry link is then created under that new key, `Everyone` will be granted `Full Control` on the target of that link during reinstall.

The PoC exploits the vulnerability using the following steps:
1. Create a subkey (named `a`) under `HKLM\SOFTWARE\Elliptic Labs\Virtual Lock Sensor\UserSettings\PluggedIn` where `Everyone` has `Full Control` with "container inherit" ("CI" flag) enabled.
2. Create a registry link (named `b`) under the newly created subkey (`a`) pointing to `HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate`.
3. Force a reinstall of Elliptic Virtual Lock Sensor.
4. Since `Everyone` now has `Full Control` on the `edgeupdate` key, the `ImagePath` value of the key can be modified to point to a payload.
5. Start the `edgeupdate` (Microsoft Edge Update Service) service to execute the payload in the context of `SYSTEM`.

## Notes
- **The exploit does not attempt to reset the permissions on the `HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate` registry key, so you will have to do that manually (and please remember to do that if you are testing this on a production system).**
- Specifically targets version 3.1.60531.2. The exploit code might require some modifications to target other vulnerable versions (the product code passed to `MsiReinstallProductW` will likely have to be changed to initiate the reinstall).
- There are different ways to turn an arbitrary registry key write into privileged code execution. This PoC achieves it by changing the configuration of an existing service (`edgeupdate`) to point to an arbitrary payload. This technique has a couple of limitations:
	- If the `edgeupdate` service is already running when the exploit is executed, the payload will not be executed. Wait a minute or two and run the exploit again.
	- If the payload is not a service binary (e.g. `cmd`), Windows will stop the execution of it after a short while.
