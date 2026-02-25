# CVE-2023-39024 and CVE-2023-39025 POC
POC for CVE-2023-39024 and CVE-2023-39025 (Harman Media Suite)

## Overview
Affected Application: Harman Media Suite

Affected Versions: 4.2.0 and under

Description: Harman Media Suite (versions 4.2.0 and below) are vulnerable to Server Side Request Forgery (SSRF) [CVE-2023-39025] and possible Local File Disclosure (LFD) [CVE-2023-39024]. This allows an unauthenticated user to potentially download attachments and recordings stored within the Media Suite application if anonymous access to the User Portal is enabled.

Requirements: "Disable view permission of User Portal for anonymous user" has to be disabled. Enabled by default, this setting allows anonymous viewing of the user portal which in turn allows for scraping of downloadable content if disabled.

Remediation: Upgrade to Harmon Media Suite V4.2.2 or higher and enable "Disable view permission of User Portal for anonymous user" inside *Configuration > Portal Settings* within the admin panel.

Public disclosure: https://mediasuite.harman.com/channel-store
