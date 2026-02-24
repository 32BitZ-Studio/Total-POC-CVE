CVE-2014-2734
=============

Ruby OpenSSL CA Private Key Spoofing

=============
 
Ruby openssl has a vulnerability when a public key is a issued prior
writing to private key and is reopened during a script it spoofs a CA
private key.

PoC script https://gist.github.com/10446549
=============
Mitre: http://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-2734
=============
SecurityFocus: http://www.securityfocus.com/bid/66956
