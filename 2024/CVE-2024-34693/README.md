# CVE-2024-34693 Exploit

This repository contains a sophisticated Python script to exploit the CVE-2024-34693 vulnerability in Apache Superset. The script sets up a rogue MySQL server and creates a malicious MariaDB connection to exfiltrate the content of a specified file from the target system.

![[Screenshot_1.png]](https://raw.githubusercontent.com/Mr-r00t11/CVE-2024-34693/main/img/Screenshot_1.png)

## Description

The `CVE-2024-34693` vulnerability allows attackers with the ability to create arbitrary database connections to perform `LOAD DATA LOCAL INFILE` attacks, resulting in the reading of arbitrary files on the target system.

## Features

- **Automated Setup**: Sets up a rogue MySQL server using Bettercap.
- **Malicious Connection**: Creates a malicious MariaDB connection to exfiltrate files.
- **Improved Logging**: Provides detailed logging for better tracking and debugging.
- **Error Handling**: Graceful error handling and meaningful error messages.

## Prerequisites

- Python 3.x
- Bettercap
- Docker and Docker Compose (for setting up the Apache Superset environment)

## Installation

1. Clone the repository:

```sh
git clone https://github.com/Mr-r00t11/CVE-2024-34693-exploit.git
cd CVE-2024-34693-exploit
```

Run the exploit script with appropriate arguments:

```sh
python3 exploit_cve_2024_34693.py http://localhost:8088 /etc/passwd
```

Replace `http://localhost:8088` with the URL of your Apache Superset instance and `/etc/passwd` with the path of the file you wish to exfiltrate.
