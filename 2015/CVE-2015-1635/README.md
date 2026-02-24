# CVE-2015-1635
CVE-2015-1635,MS15-034


###漏洞检测
    USAGE python MS15-034.py www.xxx.com:80
[测试程序](https://github.com/Zx7ffa4512-Python/CVE-2015-1635/blob/master/MS15-034.py)

###HTTP.sys远程执行代码漏洞（CVE-2015-1635，MS15-034）

远程执行代码漏洞存在于 HTTP 协议堆栈 (HTTP.sys) 中，当 HTTP.sys 未正确分析经特殊设计的 HTTP 请求时会导致此漏洞。成功利用此漏洞的攻击者可以在系统帐户的上下文中执行任意代码。



