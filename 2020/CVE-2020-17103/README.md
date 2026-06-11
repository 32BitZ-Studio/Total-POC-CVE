# MiniPlasma

After re-investigating the technique used in GreenPlasma (specifically SetPolicyVal), it turns out cldflt!HsmOsBlockPlaceholderAccess is still vulnerable to the exact same issue that was reported to Microsoft 6 years ago.
I'm not taking full credit for this, James Forshaw from google project zero found the vulnerability and reported it to Microsoft and was supposedly fixed as [CVE-2020-17103](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17103). 

However, a research who's a friend of mine pointed out that the routine might still have a vulnerability, which is something I considered but brushed off because I thought it was impossible for Microsoft to just not patch this or rollback the patch.

After investigating, it turns out the exact same issue that [was reported to Microsoft by Google project zero](https://project-zero.issues.chromium.org/issues/42451192) is actually still present, unpatched. I'm unsure if Microsoft just never patched the issue or the patch was silently rolled back at some point for unknown reasons. The original PoC by Google worked without any changes.

To highlight this issue, I weaponized the original PoC to spawn a SYSTEM shell. It seems to work reliably in my machines but success rate may vary since it's a race condition. 

I believe all Windows versions are affected by this vulnerability.

<img width="1402" height="818" alt="poc" src="https://github.com/user-attachments/assets/d94b77e5-fba5-47d8-8ae8-8cf5b3d5f686" />


