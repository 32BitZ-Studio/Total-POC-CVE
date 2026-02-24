# RuoYI 4.2 (Shiro 1.4.1) Shiro-721漏洞复现环境

用于在RuoYI上复现Shiro-721漏洞(CVE-2019-12422)。

提示：本服务存在**严重漏洞**，仅用于漏洞复现用途，请勿用于生产环境。

## 克隆
为方便安装指定版本maven和jdk，仓库使用了`git lfs`管理大文件，因此需`git lfs clone`。

不清楚这样是否违反jdk的分发原则，若有违反我将及时删除。

## 启动
`docker-compose up -d`

## 版本
+ JDK 1.8 (8u65)
+ MySQL 5.7
+ Maven 3.0
+ Base Ubuntu:22.04

## 配置参数
+ apt-get: USTC mirrors
+ mvn: Aliyun mirrors
+ MySQL字符集: utf8/utf8_unicode_ci

## 服务信息
+ HTTP: 8080
+ 默认用户: admin/admin123
