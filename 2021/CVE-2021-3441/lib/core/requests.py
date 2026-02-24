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
from lib.core.module_parser import parser


module = ''


# Connect to target and request page
def request(infile,outfile,verbosity,url,ioc_path):
    path = 'http://' + url # The IP of the vulnerable target 
    headers = {
        'Host':url, 
        'User-Agent':c.user_agent,
        'Accept':'*/*',
        'Accept-Language':'en-US,en;q=0.5',
        'Accept-Encoding':'gzip, deflate',
        'Content-Type':'text/xml',
        'Content-Length':0,
        'Connection':'close',
        'Referer':path,
    }

    sys.stdout.write(c.BIYellow)
    if verbosity == 1:
        print('{!} Scanning target: ',url,' for CVE')
        print('{!} -------- {INFO} IoC Path:',ioc_path)

    full_path = path  +  ioc_path 
    try:
        if verbosity == 1:
            sys.stdout.write(c.BIYellow)
            print('{!} -------- {INFO} Requesting ',full_path)
        response = requests.get(full_path, timeout= c.timeout_seconds)
        response.raise_for_status()
    except:
        sys.stdout.write(c.BIRed)
        if verbosity == 1:
            print('{X} -------- Timeout Exception')
    else:
        sys.stdout.write(c.BIGreen)
        if verbosity == 1:
            if response.status_code == 200: 
                print('{!} -------- {INFO}: OK Response, Status Code:',response.status_code)
                return response, url 
    return 


def check_version(url,verbosity):
    # Check target header for product version, then choose the correct module for the version found
    path = 'http://' + url # The IP of the vulnerable target 
    res = requests.get(path, timeout= c.timeout_seconds)
    server_version = res.headers["Server"]
    #     supported_versions = ['''HP HTTP Server; HP Officejet 4630 series - B4L03A; Serial Number: CN3CJ2M03D05Y0; Built:Tue Jun 16, 2020 10:22:46AM {MYM1FN2025AR}''':'./modules/hp-officejet-4630.yml']
    supported_versions = {'''HP HTTP Server; HP Officejet 4630 series - B4L03A; Serial Number: CN3CJ2M03D05Y0; Built:Tue Jun 16, 2020 10:22:46AM {MYM1FN2025AR}''':'./modules/hp-officejet-4630.yml'}
    if server_version in supported_versions:
        module = supported_versions.get(server_version)
        sys.stdout.write(c.BIYellow)
        if verbosity == 1:
            print('{!} -------- {INFO} Product Version is Supported')  
        if verbosity == 2:
            print('{!} -------- {INFO} Printer Version Detected')
            print('{!} -------- {INFO} Product Version is Supported')  
        return module
    else:
        sys.stdout.write(c.BIRed)
        if verbosity == 1:
            print('{X} -------- {ERROR} Product Version is not Supported')
        if verbosity == 2:
            print('{X} -------- {ERROR} Version Detected:',server_version)
            print('{X} -------- {ERROR} Product Version is not Supported')
            print('{X} -------- {ERROR} Exiting')
    pass
     