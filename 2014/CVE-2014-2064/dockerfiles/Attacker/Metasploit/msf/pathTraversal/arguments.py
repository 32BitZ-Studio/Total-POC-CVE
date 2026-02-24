import argparse

import database

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automation of a number of different path traversal vulnerability exploits. This script first obtains a manager account by parsing the tomcat-users.xml, and then executes an instance of Metasploit to attack the server through the compromised account. Available exploits: "+" ".join(database.EXPLOITS))
    parser.add_argument("cve", nargs=1, type=str, help="the id of the CVE to exploit")
    parser.add_argument("address", nargs=1, type=str, help="the address of the server to attack (bare ip xor domain name)")
    return parser.parse_args()

def get_CVE(args):
    return args.cve[0]

def get_address(args):
    return args.address[0]
