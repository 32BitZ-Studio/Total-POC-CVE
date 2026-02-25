# CVE-2024-31777 | GUnet OpenEclass E-learning platform Unrestricted File Upload PoC 

## 📜 Description

This script presents a proof of concept (PoC) for CVE-2024-31777, a security vulnerability discovered in GUnet OpenEclass E-learning platform with a CVSS of 9.8 which affects the endpoint of 'certbadge.php'. Authenticated attackers possessing administrative privileges are able to exploit this flaw to execute unrestricted file uploads via the ZIP functionality, thereby achieving remote code execution.



## 📜 Installation

The tool is written in Python3, and requires some modules to work correctly: 

```bash
pip3 install -r requirements.txt
```

## 🚀 Usage

Use this tool responsibly and ensure you have authorization from the target system's owner. The script requires authentication as an Administrator, and the base path of the openeclass path.

```bash
python3 CVE-2024-31777.py -u admin -p admin -e http://localhost/openeclass
```

**Parameters:**

- `-u`: Username for login.
- `-p`: Password for authentication.
- `-e`: Base URL of the Open eClass

### Proof Of Concept 

![](/assets/CVE-2024-31777_poc.png)<br>

## 📆 Changelog

### [12. April 2024] Initial Release

- Initial release showcasing the exploit for CVE-2024-31777.

### [3. April 2024] - GUnet Response

- GUnet Team confirmed the vulnerability and a hotfix is on the way for the version of 3.16

### [2. April 2024] - Demo PoC

- Demo PoC showcasing the exploit to the vendor.

## Credits

- [RoboGR00t](https://github.com/RoboGR00t) for his initial research which led me to research the OpenEclass GUnet CMS. 
- [GUnet](https://www.openeclass.org/) For the amazing work they've done all this years for the Greek community.

## 📌 Author

**Georgios Tsimpidas**
- [Website](https://freysolareye.github.io/)
- [Twitter](https://twitter.com/freysolareye)
- [LinkedIn](https://www.linkedin.com/in/george-tsimpidas/)

## ⚠️ Disclaimer

This tool is intended for educational and ethical testing purposes only. Unauthorized scanning, testing, or exploiting of systems is illegal and unethical. Ensure you have explicit, authorized permission to engage in any testing or exploitation activities against target systems.
