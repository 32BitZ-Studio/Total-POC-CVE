# NVMS-1000-Directory-Traversal-Bash
Directory Traversal Exploit written in Bash for NVMS-1000 (CVE-2019-20085).

## Usage
```
./cve-2019-20085-poc.sh -u TARGET_URL -f TARGET_FILE
```
#### Example
```
./cve-2019-20085-poc.sh -u http://127.0.0.1/ -f path/to/file.txt
```

## Disclaimer
This POC was created for educational purposes only.

## Reference
- [https://www.exploit-db.com/exploits/48311](https://www.exploit-db.com/exploits/48311)
