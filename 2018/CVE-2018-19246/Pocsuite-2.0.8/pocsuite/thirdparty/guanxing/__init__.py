# -*- coding: utf-8 -*-

"""
Guanxing library
~~~~~~~~~~~~~~~~~~~~~

Guanxing is an utils library
usage:

   >>> import guanxing

:copyright: (c) 2015 by ShuZiGuanXing.

"""

__title__ = 'guanxing'
__version__ = '0.1.0'
__build__ = 0x000100
__author__ = 'mO0n@guanxin'

from pocsuite.thirdparty.requests.packages import urllib3
from .utils import parse_ip_port, web_spider, make_verify_url,http_packet
from .dnslog import dnslog

urllib3.disable_warnings()