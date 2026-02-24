# CVE-2017-3241-POC
POC for java RMI deserialization vulnerability

You probably need to use JDK 8 to run this poc.

Just pay attention to Message class in both client and server side. They are different. And the difference is the key to understand this vulnerability.

The fix Oracle published is to have developer configure a deserialization white/black list in java security policy. I would say, how many developer would know that list exist until they got hacked?

I thought to write a testing program, but I am lazy.. if you understand my code, can easily write your own. I suggest you use java instrument or reflection.

and Remote code execution is possible if some classes exist in target classpath:

http://seclist.us/proof-of-concept-exploit-showing-how-to-do-bytecode-injection-through-untrusted-deserialization.html

https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf

http://www.freebuf.com/vuls/126499.html

This program is for Educational and test purpose ONLY. Do not use it without permission. Do not use it for malicious purpose. The usual disclaimer applies, especially the fact that me is not liable for any damages caused by direct or indirect use of the information or functionality provided by these programs. The author or any Internet provider bears NO responsibility for content or misuse of these programs or any derivatives thereof. By using this program you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of these programs is not my's responsibility.
