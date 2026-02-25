# Typecho Multiple Vulnerabilities
This repository contains the exploits of the following vulnerabilities:
* **CVE-2024-35538:** In Typecho v1.3.0 there is a Client IP Spoofing vulnerability, which allows malicious actors to falsify their IP addresses by specifying an arbitrary IP as value of "X-Forwarded-For" or "Client-Ip" headers while performing HTTP requests.
* **CVE-2024-35539:** In Typecho v1.3.0 there is a Race Condition vulnerability in the post commenting functionality, which allows an attacker to post several comments before the spam protection checks if the comments are posted too frequently.
* **CVE-2024-35540:** In Typecho v1.3.0 there is a Stored Cross-Site Scripting vulnerability in the post writing functionality, which allows an attacker with post writing privileges to inject arbitrary JavaScript code inside the preview of a post.
