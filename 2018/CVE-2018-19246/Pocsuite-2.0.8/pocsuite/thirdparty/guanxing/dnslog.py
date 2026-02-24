#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2016-2019 Shuziguanxing (http://www.shuziguanxing.com/)
@Author: mO0n@guanxin
@Created: 2019-07-01 15:15
@Usage:

# Import
from pocsuite.thirdparty.guanxing import dnslog

# Init
dns = dnslog()

# Get Domain Name
domain = dns.get_domain()

# Get Random Domain Prefix
prefix = dns.get_prefix()

# Verify DNS Query Result
ret = dns.verify(1)
if ret:
    print('Vuled')
"""

from pocsuite.api.request import req
from pocsuite.lib.utils.randoms import rand_text_alpha

import time

class dnslog():
    _TEMPATE_API_URL = 'http://api.ceye.io/v1/records?token={}&type=dns&filter={}'
    _TEMPLATE_DOMAIN = '{}.{}.ceye.io'
    _TEMPLATE_PING = {
        'wint' : ['cmd', '.', '/c', 'ping -n 1 {}'],
        'unix' : ['sh', '/bin/', '-c', 'ping -c 1 {}']
    }

    random_domain = None
    random_str = None

    token = None
    user  = None
    
    def __init__(self, api_user='emzj50', api_token='ddde5d877b62297f76ef5efc570a5627'):
        '''Init class. Parameters is DNSLog User and API token'''
        self.token = api_token
        self.user  = api_user
        self.refresh()

    def refresh(self, length = 5):
        '''Generate new random string and domain.'''
        self.random_str = rand_text_alpha(length)
        self.random_domain = self._TEMPLATE_DOMAIN.format(self.random_str, self.user)
        self.api_url = self._TEMPATE_API_URL.format(self.token, self._TEMPLATE_DOMAIN.format(self.random_str[:5], self.user))

    def get_domain(self):
        '''Get last random domain'''
        return self.random_domain

    def get_prefix(self):
        '''Get last random domain prefix'''
        return self.random_str
    
    def verify(self, retry = 3):
        '''Validate DNS Query status.
        @return string: Last 5 client ip or None. 
        '''
        while retry > 0:
            resp = req.get(self.api_url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200 and 'application/json' in resp.headers['content-type']:
                data = resp.json()
                if 'data' in data and len(data['data']) > 0:
                    ip_list = []
                    # 成功则返回最后一次DNS请求的源IP
                    for item in data['data'][:5]:
                        ip_list.append(item['remote_addr'])
                    return '\n'.join(ip_list)
            
            time.sleep(2)
            retry = retry - 1
        
        return None

    def get_ping_template(self, ostype=None):
        '''获取常见操作系统PING指令模板，域名部分用花括号占位，使用string.format()方法填充域名/IP
        例如：
        Windows下为ping -n 1 www.szgx.com
        Linux下为ping -c 1 www.szgx.com
        '''
        if ostype and ostype in self._TEMPLATE_PING:
            return {
                ostype: self._TEMPLATE_PING[ostype]
            }
        
        return self._TEMPLATE_PING