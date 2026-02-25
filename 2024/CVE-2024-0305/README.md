# cve-2024-0305exp
cve-2024-0305可用的exp，如需引用请转明出处，感谢！
## 0x01 产品背景
Ncast盈可视高清智能录播系统是广州盈可视电子科技有限公司的一款产品。该系统存在RCE漏洞，攻击者可以利用此漏洞执行任意命令能够利用该漏洞获取服务器权限，导致服务器沦陷。
## 0x02 漏洞范围
> Ncast 2007
> Ncast 2017
## 0x03 漏洞寻找
> FOFA: app="Ncast-产品"
## 0x04 使用方法
> python cve-2024-0305.py -u {YOUR TARGET} -p {TARGET PORT}
注：不带http://
## 0x05 其他事项
该脚本默认使用RCE命令为whoami，如需进一步使用可自行修改。
![1713410522433](https://github.com/jidle123/cve-2024-0305exp/assets/123531867/f327e2d2-bb75-461b-ae5f-2cd3052f0a34)

