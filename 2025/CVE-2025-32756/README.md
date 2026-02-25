# CVE-2025-32756: Fortinet RCE PoC

A proof-of-concept for the critical stack-based buffer overflow vulnerability (CVE-2025-32756) affecting Fortinet products.

## Vulnerability

- **CVSS**: 9.8 (Critical)
- **Type**: Stack-based buffer overflow in AuthHash cookie processing 
- **Impact**: Unauthenticated remote code execution
- **Affected Products**: FortiVoice, FortiMail, FortiNDR, FortiRecorder, FortiCamera

The vulnerability exists in the processing of the `enc` parameter in the `/remote/hostcheck_validate` endpoint, where improper bounds checking allows buffer overflow.

## Usage

### Exploit a single target
```
python3 fortinet_cve_2025_32756_poc.py exploit target_ip [-p port] [-d]
```

### Scan for vulnerable devices

#### Scan a single IP
```
python3 fortinet_cve_2025_32756_poc.py scan -f 192.168.1.1 [-p port] [-t threads] [-o output.csv] [-d]
```

#### Scan multiple IPs from a file
```
python3 fortinet_cve_2025_32756_poc.py scan -u targets.txt [-p port] [-t threads] [-o output.csv] [-d]
```

#### Scan an IP range
```
python3 fortinet_cve_2025_32756_poc.py scan --range 192.168.1.0/24 [-p port] [-t threads] [-o output.csv] [-d]
```

### Arguments:
- `-f, --ip`: Single IP to scan
- `-u, --file`: File containing list of IPs to scan (one per line)
- `--range`: IP range to scan in CIDR notation (e.g., 192.168.1.0/24)
- `-p, --port`: Target port (default: 443)
- `-t, --threads`: Number of threads for scanning (default: 10)
- `-o, --output`: Output file to save results (CSV format)
- `-d, --debug`: Enable debug output



## Mitigation

Update to patched versions:
- FortiVoice: 7.2.1+, 7.0.7+, 6.4.11+
- FortiMail: 7.6.3+, 7.4.5+, 7.2.8+, 7.0.9+
- FortiNDR: 7.6.1+, 7.4.8+, 7.2.5+, 7.0.7+
- FortiRecorder: 7.2.4+, 7.0.6+, 6.4.6+
- FortiCamera: 2.1.4+
  
## IMPORTANT SECURITY NOTICE

This Proof-of-Concept (PoC) is designed for educational and security research purposes **only**. Please note the following:

- THIS POC DOES NOT PERFORM ACTUAL CODE EXECUTION.

- This PoC demonstrates the vulnerability by:
  - Detecting vulnerable Fortinet devices.
  - Triggering the buffer overflow condition.
  - Modifying a single byte in memory to prove successful exploitation.

- It DOES NOT:
  - Execute arbitrary code.
  - Provide shell access.
  - Install backdoors or persistence mechanisms.
  - Perform any destructive actions.


