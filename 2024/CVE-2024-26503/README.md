# Open eClass RCE Exploit Tool

This tool is designed to exploit a known vulnerability (CVE-2024-26503) in Open eClass platforms, allowing for remote code execution (RCE) through an unrestricted file upload flaw. The vulnerability allows attackers to upload a web shell to the server, enabling the execution of arbitrary commands.

## Disclaimer

This tool is intended for educational and ethical security testing purposes only. I am not responsible for any misuse or damage caused by this tool. Users must have explicit permission to test the target systems.

## Prerequisites

Before using this tool, ensure you have Python 3.x installed on your system. You will also need the `requests` library, which can be installed using pip:

```sh
pip install requests
```

## Installation

Clone the repository or download the source code:

```sh
git clone https://github.com/RoboGR00t/Exploit-CVE-2024-26503
cd Exploit-CVE-2024-26503
```

No additional installation steps are required.

## Usage

The script requires three mandatory parameters:

- `-u`, `--username`: The username for login to the Open eClass platform.
- `-p`, `--password`: The password for login.
- `-e`, `--eclass`: The base URL of the Open eClass platform you wish to target.

Run the script with the required parameters like so:

```sh
python exploit-cve-2024-26503.py -u 'username' -p 'password' -e 'http://target-open-eclass.local'
```

![img](https://github.com/RoboGR00t/Exploit-CVE-2024-26503/raw/main/img.png)

## Cleanup

The script attempts to remove the uploaded web shell upon exiting the command execution mode. However, manual verification is recommended to ensure no traces are left behind.


## Acknowledgments

- Thanks to all the cybersecurity researchers and ethical hackers who contribute to the security community.
- Special thanks to the Open eClass team for their continuous efforts in improving platform security.



> **Please use this tool responsibly and ethically.**
