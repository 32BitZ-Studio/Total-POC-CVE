# CVE-2024-23780 Exploit for Netbox

This script exploits CVE-2024-23780, which allows remote code execution (RCE) on Netbox instances.

## Usage

python netbox_exploit.py --url <netbox_url> --username <netbox_username> --password <netbox_password>


## Parameters

- `--url`: URL of the Netbox instance.
- `--username`: Username for authentication with the Netbox instance.
- `--password`: Password for authentication with the Netbox instance.

Ensure you have appropriate permissions before running this script on any Netbox instance.
