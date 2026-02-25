# CVE-2023-3722
Python POC for CVE-2023-3722 Avaya Aura Device Services Unrestricted File Upload RCE. 

This script will use a `PUT` request to upload a php file with an eight-digit randomly generated filename. Then it will make a `GET` request to retrieve this file and parse the output to get the command output. 


## Running

```
python3 ./CVE-2023-3722.py example.com:444 --query "id"
```

```
python3 ./CVE-2023-3722.py example.com:444 --query "hostname"

```

