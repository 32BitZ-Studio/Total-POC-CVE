# -Insecure-Local-Storage-of-Sensitive-User-Data-in-PhonePe-Android-App-Unpatched-


_Discovered by [hc4](https://github.com/honestcorrupt/)_  
_Date Reported: April 2025_  
_CVE Status: CVE Requested (Pending)_
CVE Request 1862785 for CVE ID Reques

---

## 📌 Overview

A critical local vulnerability was discovered in the PhonePe Android app (tested on v25.03.21.0), where sensitive user data — including authentication tokens, PII, and KYC metadata — is stored unencrypted in the app's local SQLite databases.

Any attacker or malicious app with root access can extract these values and reuse them against production APIs for account takeover and financial fraud.

---

## 🧠 Technical Summary

**Affected Package:** `com.phonepe.app`  
**Tested Version:** `25.03.21.0`  
**Database Path:**  

/data/data/com.phonepe.app/databases/
├── user_info.db
├── phonepe_core
├── AthenaDatabase



### Data Stored in Cleartext:

- `access_token` and `refresh_token`  
- User full name, email, phone number  
- Aadhaar (last 4 digits), PAN  
- Bank account number, IFSC, VPA  
- Verified flags (KYC passed)

---

## 🔓 Threat Model

An attacker with:

- Rooted access
- Local malware / privilege escalation
- Physical access (temporary)

...can silently extract this data and call production endpoints like:



GET /v1/user/account
Host: api.phonepe.com
Authorization: Bearer <stolen_token> 

🧪 Proof of Concept (PoC)

A detailed PoC is provided in the `POC/` folder, including:

- Step-by-step ADB extraction  
- SQLite schema & queries  
- Redacted token + KYC data  
- Sample API abuse with `curl`
- 📺 Watch the PoC Video:
- https://drive.google.com/drive/folders/1Xj9y2w3E98IZu8PUeGGI0nQPNsvVm87I?usp=sharing

---

🧨 Impact

- 🔐 Account takeover via token replay  
- 🧾 Identity theft via Aadhaar/PAN data  
- 📞 Social engineering using verified phone numbers  
- ⚖️ Regulatory exposure under DPDP (India), GDPR (EU), PCI-DSS

🧠 Disclosure Timeline Table Fix:

Instead of this:

📆 Disclosure Timeline
Date	Event
April 2025	Vulnerability discovered

📆 Disclosure Timeline

| Date         | Event                                                         |
|--------------|---------------------------------------------------------------|
| April 2025   | Vulnerability discovered and reported to PhonePe via BugBase |
| April 22, 2025 | Report marked "Invalid" (rooted device = out of scope)     |
| May 2, 2025  | CVE requested via MITRE                                       |
| May 13, 2025 | Public advisory released on GitHub                            |
| TBA          | CVE published                                                 |




🤝 Credits
---
    Researcher: Soyam Arya (hc4)

    Linkedin: https://www.linkedin.com/in/soyam-arya-a90356312/ 

    Contact: soyamarya96ethical@gmail.com



---

📄 🔥 Final Description

The PhonePe Android application (tested on version 25.03.21.0) stores highly sensitive user data — including authentication tokens (`access_token`, `refresh_token`), KYC metadata (Aadhaar, PAN), personal identifiers (full name, phone number, email), and bank account information — in plaintext within local SQLite databases (`user_info.db`, `AthenaDatabase`, `phonepe_core`) located inside the app's private storage directory.

These databases are not encrypted and do not use Android's Keystore or any secure local storage mechanism. As a result, any malicious app, malware, or attacker with root access to the device can extract this data and use it to:

- Hijack the user’s PhonePe account via token replay (no OTP or MFA required)
- Access verified financial details and KYC metadata
- Conduct identity theft, phishing, and targeted financial fraud

This vulnerability has been verified on a rooted Android 11 device using the researcher's own account. It has not been exploited against others and was disclosed responsibly. PhonePe acknowledged the report via their VDP platform but declined to act due to out-of-scope policy on rooted devices.

Impact includes account takeover, exposure of verified financial data, and violation of privacy and compliance standards such as DPDP, GDPR, and PCI-DSS.





**CVE_Confirmed**   

![CVE-2025-5154](https://github.com/user-attachments/assets/776b2f6d-90bc-47f2-8298-38c3e76d6edf)
![life's first CVE pic 2 ](https://github.com/user-attachments/assets/ce1927ab-e0ac-4b77-8f34-f48093e6ef98)

Check out the CVE details here : https://vuldb.com/?id.310242

Thanks a lot VulnDB Team and VulDB Moderation Team......


**Note : This critical vulnerability in the PhonePe Android app (CVE-2025-5154) was discovered and responsibly reported by me, Soyam Arya (aka honest_corrupt in the cybersecurity community). This CVE highlights a severe information disclosure issue that could impact millions of users. I'm proud to contribute to making digital platforms safer, and I appreciate the CVE team's recognition of this finding.*










