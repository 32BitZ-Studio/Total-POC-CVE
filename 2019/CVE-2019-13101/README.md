# DLKPloiT600.py
Simple Python script for D-Link vulnerability scan and test 

- [CVE-2019-13101]
- (https://nvd.nist.gov/vuln/detail/CVE-2019-13101)
- (https://www.cvedetails.com/cve/CVE-2019-13101/)
- (https://us.dlink.com/en/security-advisory)
- (https://www.dlink.com/en/security-bulletin)


[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

## Requirements:

- python3.x
- requests

  * $ pip install -r requirements.txt

## Usage:

$ python3 dlkploit600.py -H [target] --range [ip-range] -p [port] [OPTIONS]

Options:

-H, --host
-s, --scan
--range (Use this format: 192.168.0.1-254)
-r --scannerdlrange


help, --help, -h
