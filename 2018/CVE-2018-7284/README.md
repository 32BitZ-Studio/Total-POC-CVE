# astDoS
Tool to exploit CVE-2018-7284 and CVE-2018-19278

## Usage
This tool is used as a command.

```
astDoS.py [-h] [-a {1,2}] [-sA SERVER_IP] [-sP SERVER_PORT] [-u USER]
                 [-p PASSWD] [-sub SUBUSER] [-dA DNS_IP] [-dP DNS_PORT]
                 [-v [VERSION]]

DoS attack against Astersisk, CVE-2018-7284 and CVE-2018-19278

optional arguments:
  -h, --help            show this help message and exit
  -a {1,2}, --attack {1,2}
                        Attack type. 1 for CVE-2018-7284 header (default
                        value). 2 for CVE-2018-19278 DNS
  -sA SERVER_IP, --server-address SERVER_IP
                        CVE-2018-7284 headers: Asterisk IP address to connect
                        to
  -sP SERVER_PORT, --server-port SERVER_PORT
                        CVE-2018-7284 headers: Astersik port to connect to
                        (5060 by default)
  -u USER, --user USER  CVE-2018-7284 headers: username to use in the attack
  -p PASSWD, --password PASSWD
                        CVE-2018-7284 headers: password to use in the attack
  -sub SUBUSER, --subscribeUser SUBUSER
                        CVE-2018-7284 headers: subscribe user to use in the
                        attack
  -dA DNS_IP, --dns-address DNS_IP
                        CVE-2018-19278 DNS: Address to bind the socket
  -dP DNS_PORT, --dns-port DNS_PORT
                        CVE-2018-19278 DNS: Port to bind the socket
  -v [VERSION], --version [VERSION]
                        Show tool version.

```
