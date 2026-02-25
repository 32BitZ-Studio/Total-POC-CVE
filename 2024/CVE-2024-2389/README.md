# Progress Kemp Flowmon CVE-2024-2389

## Description
This repository contains a Python script to exploit a vulnerability in Flowmon that allows for gaining a reverse shell on the target system. The exploit leverages a flaw in the `service.pdfs/confluence` endpoint to execute arbitrary commands on the server, resulting in a reverse shell connection.

## Usage
1. Clone the repository to your local machine:
   ```bash
   https://github.com/adhikara13/CVE-2024-2389.git
   ```

2. Navigate to the cloned directory:
   ```bash
   cd CVE-2024-2389
   ```

3. Run the Python script:
   ```bash
   python main.py
   ```

4. Follow the prompts to input the Flowmon host, your IP address, and the desired port.

## Disclaimer
This exploit is for educational purposes only. Unauthorized use of this script against systems you do not own or have explicit permission to test is illegal and unethical. Use at your own risk.

## Requirements
- Python 3.x
- Requests library (`pip install requests`)

## Contributing
Contributions are welcome! Feel free to submit pull requests or open issues for any improvements, bug fixes, or suggestions.