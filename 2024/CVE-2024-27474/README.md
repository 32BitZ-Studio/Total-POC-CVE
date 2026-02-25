# Leantime-POC
CVE-2024-27474, CVE-2024-27476, CVE-2024-27477

## Description 

The following vulnerabilities were identified in version 3.0.6 of the Leantime goals focused project management system.

### CVE-2024-27474
A cross-site request forgery (CSRF) vulnerability which, when triggered, would create and elevate the privileges of an account to the administrator role. 

### CVE-2024-27476
An HTML injection vulnerability which allows an attacker to inject malicious HTML code, through href attribute or anchor tags, into the application. In my proof-of-concept (POC) I used this to redirect the "victim", otherwise known as myself, to an attacker-controlled login page where they may have their credentials stolen. 

### CVE-2024-27477
A cross-site scripting (XSS) vulnerability, which, when triggered, issues a request to a remote server, performing a server-side request forgery attack. This could be leveraged to steal the cookies of any unsuspecting user who visits the page on which it is stored. 
