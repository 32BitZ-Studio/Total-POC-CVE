# CVE-2016-4669
不完美的利用代码，只能用于学习:)

#1 编译方法
make就可以了

#2 功能
如果运行成功，可以获得root权限。但是成功率并不高。

#3 大致情况
- 比较稳定的制造一个dangling port。
- 不能稳定的让带有root的port重用，10次能成功1次吧：（，可能更低
- 不是很稳定，很容易把内核弄崩溃，只能用于理解和分析该漏洞的成因和利用原理
- 应该不会再去加以完善了，不过还是期待有大腿能指点一下更稳定的触发方法。

#4 writeup
[这里](http://turingh.github.io/2017/01/15/CVE-2016-7644-%E4%B8%89%E8%B0%88Mach-IPC/)

#5 运行成功的结果
![1](https://raw.githubusercontent.com/turingH/CVE-2016-4669/master/EFA15327-ED77-4B03-A898-29CB767A72B5.png)

