import socket
import struct
import sys

banner = """
      _                        _       _               _   
     | |                      | |     | |             | |  
  ___| |_ ___ _ __ _ __   __ _| | __ _| |__   ___  ___| |_ 
 / _ \ __/ _ \ '__| '_ \ / _` | |/ _` | '_ \ / _ \/ __| __|
|  __/ ||  __/ |  | | | | (_| | | (_| | | | | (_) \__ \ |_ 
 \___|\__\___|_|  |_| |_|\__,_|_|\__, |_| |_|\___/|___/\__|
                                  __/ |                    
                                 |___/                     
                                    
\t\t\t\t\tby AWARE7 GmbH
"""
print(banner)

if len(sys.argv) < 2:
    print("Not enough Arguments")
    print("python3 scanner.py <IP-Address>")
    sys.exit()

# Connection-Handle for SMB Handshake
pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
# Generate a Socket
sock = socket.socket(socket.AF_INET)
sock.settimeout(3)
# Get Hostname
hostname = sys.argv[1]
# Connect to Host
print("Scanning System: {}\r\n".format(hostname))
sock.connect(( hostname,  445 ))
# Send Handshake
sock.send(pkt)

# Receive Handshake
nb, = struct.unpack(">I", sock.recv(4))
res = sock.recv(nb)

# Check if SMB Version 3_11 is used
if not res[68:70] == b"\x11\x03":
    print("\tYour System {} doesn't use the latest SMB Version. This is insecure as well but you are not effected by CVE-2020-0796".format(hostname))
    sys.exit(1)

# Check if uses Compression 
if not res[70:72] == b"\x02\x00":
    print("\tYour System {} is not vulnearble to CVE-2020-0796".format(hostname))
    sys.exit(1)

print("\tYour System {} is vulnearble to CVE-2020-0796".format(hostname))
sys.exit(1)