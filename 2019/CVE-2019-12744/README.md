# CVE-2019-12744
 
## Information
Exploit Title: Remote Command Execution through Unvalidated File Upload in SeedDMS versions < 5.1.11 <br>
CVE: CVE-2019-12744 <br>

Vendor Homepage: https://www.seeddms.org/index.php?id=2 <br>
Exploit Author: NobodyAtall <br>
Tested version: Seeddms 5.1.10, 5.0.11 <br>
Tested OS: Windows 7 x64

## Medium Article
https://bryanleong98.medium.com/cve-2019-12744-remote-command-execution-through-unvalidated-file-upload-in-seeddms-versions-5-1-1-5c32d90fda28

## PoC Images
![](pocImg/1.png)

![](pocImg/2.png)

## Help Menu
```
usage: CVE-2019-12744.py [-h] -u USERNAME -p PASSWORD --url URL

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        login username
  -p PASSWORD, --password PASSWORD
                        login password
  --url URL             target URL Path
```

