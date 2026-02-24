# Solr Velocity模板注入漏洞检测工具
## 工具介绍
19年10月底爆出了Solr Velocity模板注入远程命令执行漏洞，人工检测该漏洞需burp抓包改包来回好几次，效率较低，写了这个小工具，支持一键检测漏洞、执行命令、反弹shell，欢迎提issue。该工具仅限安全从业者在法律法规允许的范围内使用，违规使用后果自负。


## 运行环境
跨平台，JRE>=1.8。

（为精简文件大小，单独为每个平台打包SWT库，下载对应平台jar即可）

## 运行方式
win：java -jar SolrVulScan1.0-win64.jar

linux：java -jar SolrVulScan1.0-linux64.jar

mac：java -jar -XstartOnFirstThread SolrVulScan1.0-mac64.jar

## 运行截图
#### 检测漏洞
![](https://github.com/SDNDTeam/SolrVulScan/raw/master/screenshot/p1.PNG "检测漏洞")
#### 执行命令
![](https://github.com/SDNDTeam/SolrVulScan/raw/master/screenshot/p2.PNG "执行命令")
#### 反弹shell
![](https://github.com/SDNDTeam/SolrVulScan/raw/master/screenshot/p3.PNG "反弹shell")
#### 反弹成功
![](https://github.com/SDNDTeam/SolrVulScan/raw/master/screenshot/p3-2.jpg "反弹成功")

## 漏洞修复
请及时前往官方网站下载最新版本，网址：http://lucene.apache.org/solr/downloads.html
