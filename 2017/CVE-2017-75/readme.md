# EXP-CVE-2017-75

This Python script is designed to check for and exploit a specific vulnerability in NGINX servers (referred to as CVE-2017-75). This was developed for a public vulnerability disclosure program, I recently submitted a report to.

It uses a crafted `Range` header to potentially trigger an overflow, allowing for the retrieval of sensitive information from the server's memory.

## Features

- **Check Mode**: Quickly check if a target URL is vulnerable without performing the full exploit.
- **Exploit Mode**: If the target is vulnerable, attempt to exploit this vulnerability to retrieve memory contents.
- **Hex Dump**: Provides a hexadecimal and ASCII view of the memory contents that have been retrieved.

## Requirements

- Python 3.6+
- `requests` library

To install required Python libraries:

```bash
pip install requests
```

## Usage

```bash
python exploit.py <URL> [options]
```

### Arguments

- `url`: The target URL where the NGINX server is running.
- `-c`, `--check`: Optional flag to only check if the target is vulnerable.

### Example

To check if a target is vulnerable:

```bash
python exploit.py http://example.com --check
```

To execute the exploit against a vulnerable target:

```bash
python exploit.py http://example.com
```

## Debugging

This script includes detailed debug outputs that will guide you through each step it performs, providing insights into what is being sent and received.

## Disclaimer

This tool is intended for educational purposes and security testing within a legal framework only. The author is not responsible for any misuse or damage caused by this program.

## Author

CalebFin

