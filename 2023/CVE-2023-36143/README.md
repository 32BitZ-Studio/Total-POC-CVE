# CVE-2023-36143

PoC of CVE-2023-36143 - Maxprint Maxlink 1200G v3.4.11E

## Command Injection


## Steps to Reproduce:

1. Log in the equipment via your web browser
2. Go to the diagnostic tool
3. Insert any ip, e.g 127.0.0.1, the ; character and a command.
4. Example: 127.0.0.1;cat /etc/passwd
