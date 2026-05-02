# Private → Public Disclosure Checklist  
A structured workflow for safely converting a private security repository into a public one.

---

## 0. Pre‑Disclosure Validation
- [ ] Vendor advisory has been published  
- [ ] Vendor has explicitly granted permission to disclose  
- [ ] Disclosure deadline has passed (e.g., 90 days)  
- [ ] Vendor marked the case as “Won’t Fix” and disclosure is appropriate  
- [ ] No NDA, embargo, or contractual restriction applies  
- [ ] No sensitive data remains in the repository  

---

## 1. Repository Hygiene
- [ ] Remove dangerous PoC elements  
- [ ] Remove vendor internal emails or confidential communication  
- [ ] Remove logs containing sensitive information  
- [ ] Remove exploit automation scripts not intended for public release  
- [ ] Sanitize screenshots (no internal systems or identifiers)  
- [ ] Validate `metadata.json`  
- [ ] Validate `README.md`  

---

## 2. Documentation Review
- [ ] README follows the standardized template  
- [ ] Discoverer is correctly listed as:  
      **gregk4sec (https://github.com/gregk4sec/cve)**  
- [ ] Technical analysis is complete and accurate  
- [ ] Disclosure timeline is correct  
- [ ] Severity is correct (CVSS or vendor rating)  
- [ ] References link to official advisories  
- [ ] Repository name follows naming conventions  

---

## 3. PoC Sanitization
- [ ] Safe PoC prepared (non‑weaponized)  
- [ ] Partial PoC prepared (if needed)  
- [ ] Full PoC prepared (only if safe and patch is available)  
- [ ] No PoC (if exploitability is too dangerous)  
- [ ] Remove sensitive data from PoC files  

---

## 4. Metadata & Summary Integration
- [ ] Add repository to `repo-list.txt` in the main archive  
- [ ] Ensure `metadata.json` is complete  
- [ ] Set `status = Public`  
- [ ] Trigger or wait for automated `summary.md` rebuild  

---

## 5. Final Checks
- [ ] Repository name is correct  
- [ ] Repository description is correct  
- [ ] Tags/topics are correct  
- [ ] No draft files or TODO notes remain  
- [ ] No private branches contain sensitive material  

---

## 6. Publish
- [ ] Change repository visibility → **Public**  
- [ ] Verify README renders correctly  
- [ ] Verify all links work  
- [ ] Verify `summary.md` updated correctly  

---

## 7. Optional Post‑Disclosure Actions
- [ ] Public announcement (X/Twitter, blog, etc.)  
- [ ] Notify vendor (if required)  
- [ ] Add to LinkedIn or portfolio  
- [ ] Add repository badges (CVE / MSRC / Google / Oracle)  
