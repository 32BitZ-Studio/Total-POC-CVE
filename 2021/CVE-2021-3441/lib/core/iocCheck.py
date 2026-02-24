import requests
import json
import sys
import getopt 
import urllib
import os 
import subprocess 
import re
import datetime
from bs4 import BeautifulSoup as bs
import lib.core.constants as c 
import lib.utils.printer as printer

def check_header(response,verbosity):
    server_version = response.headers["Server"]
    supported_versions =['HP HTTP Server; HP Officejet 4630 series - B4L03A'] ## TODO: Read c.modules instead 
    flag = False
    for opt in supported_versions:
        if opt in str(server_version):
            flag = True
    if verbosity == 1:
        print('{!} -------- {INFO} Supported Server Version Detected')
        print('{!} -------- {INFO} Server Version:',server_version)
    return

# parse url response body and search for content of fields vulnerable to xss
def find_compromise(response,verbosity,html_tag):
    soup = bs(response.text, 'html.parser')
    vuln_field = soup.find(html_tag.lower())
    if verbosity == 1:
        print('{!} -------- {INFO} Searching for Entries in ',html_tag)
    if verbosity == 4:
        print('{!} -------- {DEBUG} vuln_field',len(vuln_field))

    print('{DEBUG} vuln_field', vuln_field)
    print('{DEBUG} FIELD_GET_TEXT:',)

    for item in vuln_field:
        if item:
            print('{DEBUG} item ', item)
            if verbosity == 1:
                sys.stdout.write(c.BIYellow)
                print('{!} -------- {INFO}: Found Something in DeviceLocation Field')
                out = check_content(item,verbosity)
                return out
        else:
            if verbosity == 1:
                sys.stdout.write(c.BIGreen)
                print('{!} Nothing Found')
                print('{!} Item:',item.get_text())
            else:
                continue  
    return 

def check_content(payload,verbosity):
    if verbosity == 1:
        print('{!} -------- {INFO}: Checking for Suspicious characters')
    flag = False
    for char in c.badchars:
        if char in str(payload):
            flag = True
            continue   # conduct tests on this 
    if flag:
        if verbosity == 1:
            sys.stdout.write(c.BIRed)
            print('{!} -------- {WARNING}: Found Indicator of Compromise')
            print('{!} -------- {WARNING}: Field Setting :'+str(payload))
        flag = False  # conduct tests on this 
        return str(payload)
    else:         
        sys.stdout.write(c.BIGreen)
        if verbosity == 1:
            print('{!} -------- {OK}: No IoCs Detected')
            print('{!} -------- {OK}: Payload:', str(payload))
    return
