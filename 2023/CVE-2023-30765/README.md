# CVE-2023-30765
CVE-2023-30765 / ZDI-23-905 -  Delta Electronics Infrasuite Device Master Privilege Escalation

Bug credit: Piotr Bazydlo (@chudypb) <br>
Links:
  - https://www.zerodayinitiative.com/advisories/ZDI-23-905/
  - https://www.cisa.gov/news-events/ics-advisories/icsa-23-180-01

### Usage
```
python3 cve-2023-30765.py -h
usage: cve-2023-30765.py [-h] -i TARGET [-p PORT] [-t] [--user USER] [--pass PWD] [-b]

Delta Electronics Infrasuite Device Master Privilege Escalation (CVE-2023-30765)

optional arguments:
  -h, --help            show this help message and exit
  -i TARGET, --target TARGET
                        Target Infrasuite instance
  -p PORT, --port PORT  Target webservice port (default:80)
  -t, --tls             Target webservice has tls (default:false)
  --user USER           Account to escalate
  --pass PWD            Account password
  -b, --brute           Brute-force default user:pass pairs
```
### FYI
Couldnt find a way to enumerate group contents so this just adds the given user to the admins group with the original administrator. Might be temperamental for other users in that group. ymmv, yolo. 
