# CVE-2016-4971
On a server redirect from HTTP to a FTP resource, wget would trust the HTTP server and uses the name in the redirected URL as the destination filename.

See the [post](https://blog.0xbbc.com/2016/06/wget%E6%BC%8F%E6%B4%9Ecve-2016-4971/) on my blog for some detail.

### Usage
On your server, 
```node wget.js```

On your test computer, 
```wget http://url.to.your/server```

### Screenshots
![screenshot 1](https://raw.githubusercontent.com/BlueCocoa/CVE-2016-4971/master/screenshot-1.jpg)

![screenshot 2](https://raw.githubusercontent.com/BlueCocoa/CVE-2016-4971/master/screenshot-2.jpg)
