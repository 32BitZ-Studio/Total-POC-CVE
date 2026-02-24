#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2016-2018 Shuziguanxing (http://www.shuziguanxing.com/)
@Author: mO0n@guanxin
@Created: 2018-12-10 14:15
"""

from pocsuite.thirdparty import requests as req
from urlparse import urlparse, urljoin
import re
import os

def make_verify_url(url,payload,mod = 1):
    '''
    payload 样例：/index.php?id=xxxx
   
    构造固定uri漏洞url
    1，默认mod = 1返回根路径。
    2，当mod = 0 返回当前url路径。
    '''

    if payload and payload[0] != '/':
        payload = '/' + payload

    verify_url = ''
    url_obj = urlparse(url)
    if url_obj.scheme and url_obj.netloc:
        # URL当前路径处理
        if mod == 1:
            dir_path = os.path.dirname(url_obj.path)
            if dir_path == '/':
                dir_path = ''
            verify_url = url_obj.scheme + '://' + url_obj.netloc + dir_path + payload
        # URL根路径处理
        if mod == 0:
            verify_url = url_obj.scheme + '://' + url_obj.netloc + payload

    return verify_url

def parse_ip_port(url, default_port = 0):
    '''将url格式数据转化成ip&port数据
    @param url string: URL
        url = https://x.x.x.x:8443
        url = https://x.x.x.x
        url = x.x.x.x
        url = x.x.x.x:80
    @return: (IP,Port)
    '''
    host, path = '', ''
    if '/' not in url:
        host = url
    else:
        if '://' not in url:
            host = url[:url.find('/')]
            path = url[url.find('/'):]
        else:
            host = urlparse(url).netloc
            path = url[url.find(host) + len(host):]
    
    if len(host) == 0:
        host = url
    
    if ":" in host:
        ip, port = host.split(":")
    else:
        ip = host
        # 预定义默认端口
        if 'https://' in url:
            port = 443
        elif 'http://' in url or host + '/' in url:
            port = 80
        else:
            port = default_port
    
    if '://' not in url:
        scheme = 'https' if default_port == 443 else 'http'
        url = '{}://{}:{}{}'.format(scheme, ip, port, path)
    
    return url, ip, int(port)


"""
Copyright (c) 2016-2019 Shuziguanxing (http://www.shuziguanxing.com/)
@Author: wuwei
@Created: 2019-09-20 15:15
@Usage:

# Import
from pocsuite.thirdparty.guanxing import http_packet

# Return Request packet and Response packet
result['VerifyInfo'] = http_packet(resp)
"""
def http_packet(resp):
    try:
        Request_Packet = ''
        Request_Packet += resp.request.method+' '+resp.request.path_url+' HTTP/1.1\r\n'
        Request_Packet += 'Host: '+urlparse(resp.request.url).netloc+'\r\n'
        for key in resp.request.headers:
            Request_Packet += key+': '+resp.request.headers[key]+'\r\n'
        if resp.request.method == 'POST' or resp.request.method == 'PUT':
            Request_Packet += '\r\n'+str(resp.request.body)+'\r\n\r\n'

        # print Request_Packet

        Reponse_Packet = ''
        Reponse_Packet += 'HTTP/1.1 '+str(resp.status_code)+'\r\n'
        for key in resp.headers:
            Reponse_Packet += key+': '+resp.headers[key]+'\r\n'
        Reponse_Packet += '\r\n'+str(resp.text)

        return {"Request_Packet":Request_Packet,"Reponse_Packet":Reponse_Packet}
    except Exception as e:
        pass
    return {"Request_Packet":"","Reponse_Packet":""}


class web_spider():
    '''网页爬虫'''

    session = None
    max_page = 0

    def __init__(self):
        self.session = req.Session()

    def __exit__(self, *args):
        self.session.close()
    
    def get_links(self, url, filter = '/cgi-bin/', size=5, depth=1, per_folder=5, total_pages=5, timeout=5, interval=0.05):
        '''递归爬取多个URL
        @param url string: 起始URL
        @param filter string: URL过滤器，支持正则表达式
        @param size int: 爬取的URL数量
        @param depth int: 递归爬取的层数
        @param per_folder int: 每次递归处理的下级URL数量
        @param total_pages int: 递归处理的总页面数
        @param timeout int: 单个URL的超时时间
        @param interval int: 两次请求之间的间隔时间
        '''
        result = {}
        self.max_page = self.max_page + 1
        try:
            resp = self.session.get(url, timeout=timeout, verify=False)
            resp.close()
            if resp.status_code in [400, 404, 405, 406, 502]:
                return {}
            
            m = re.search(filter, url, re.I)
            if m:
                result[url] = resp.status_code
            
            if depth < 1:
                return result
            
            # HTML
            match = re.findall(r'''(?:href|action|src)\s*?=\s*?(?:"|')\s*?([^'"]*?)\s*?(?:"|')\s*?''', resp.content)
            if filter:
                # JS
                match = match + re.findall(r'([^\'"?#\s=]*?{}[^\'"]+)'.format(filter), resp.content)
            # Meta refresh
            match = match + re.findall(r'content="\d+;\s*url=([^\s]+?)"', resp.content, re.I)
            
            match = list(set(match))
            max_child = per_folder
            for item_url in match:
                item_url = item_url.strip()
                if item_url == '':
                    continue
                
                if not item_url.startswith('http://') and not item_url.startswith('https://'):
                    item_url = urljoin(url, item_url)
                else:
                    # 判断是否同一网站
                    src = urlparse(url)
                    dst = urlparse(item_url)
                    if src.scheme != dst.scheme or src.netloc != dst.scheme:
                        continue
                
                if item_url in result:
                    continue
                
                real_url = item_url
                if real_url.find('#') > 0:
                    real_url = real_url[:real_url.find('#')]
                if real_url.find('?') > 0:
                    real_url = real_url[:real_url.find('?')]

                if real_url[-3:] in ['.js', '.gz', '7z']:
                    continue
                if real_url[-4:] in ['.css', '.jpg', '.gif', '.png', '.bmp', '.ico', '.txt', '.zip', '.rar', '.cat', '.ocx', '.exe', '.doc', '.xls', '.pdf', '.mov', '.avi', '.mp3', '.mid']:
                    continue
                if real_url[-5:] in ['.less', '.font', '.jpeg']:
                    continue

                next_depth = depth - 1
                next_size = size - len(result)
                if max_child > 0 and next_depth >= 0 and next_size > 0 and self.max_page < total_pages:
                    item_result = self.get_links(item_url, filter, next_size, next_depth, per_folder, total_pages, timeout, interval)
                    result.update(item_result)
                    max_child = max_child - 1
                
                if len(result) >= size:
                    break
            
            return result
        except Exception, e:
            return {}
    
    def get_link(self, url, file_exts = ['action', 'jsp', 'do', 'screen']):
        '''根据URL和扩展名获取符合条件的URL
        @param url string: 起始URL
        @param file_exts array: 允许爬取的URL对应的扩展名
        @return url or ''
        '''
        rnt = ''
        try:
            page_content = req.get(url, verify=False, timeout=5).content
            # print page_content
            # 根据后缀提取
            match = re.findall(r'''(?:href|action|src)\s*?=\s*?(?:"|')\s*?([^'"]*?\.(?:%s))''' % '|'.join(file_exts), page_content)
            # print match
            for item_url in match:
                if not item_url.startswith('http://') and not item_url.startswith('https://'):
                    item_url = self.getAbsoluteURL(url, item_url)
                elif not self.isSameDomain(item_url, url):
                    continue
                
                if self.is_url_exist(item_url):
                    rnt = item_url
                    break
            
            return rnt
        except Exception, e:
            # raise e
            return rnt

    def getAbsoluteURL(self, base, url):
        url1 = urljoin(base, url)
        return url1

    def is_url_exist(self, url):
        try:
            page_status_code = req.get(url,verify=False,timeout=5).status_code
            if int(page_status_code) != 404:
                return True
            else:
                return False
        except:
            return False

    def isSameDomain(self, url1, url2):
        try:
            if urlparse(url1).netloc.split(':')[0] == urlparse(url2).netloc.split(':')[0]:
                return True
            else:
                return False
        except Exception, e:
            return False
