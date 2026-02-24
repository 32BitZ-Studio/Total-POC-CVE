#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import imp
import re
import os
import hashlib

from pocsuite.lib.core.data import kb

kb.registeredPocs = {}

def calc_file_md5(path):
    '''计算文件的MD5'''
    fp = open(path)
    data = fp.read()
    fp.close()

    return hashlib.md5(data).hexdigest()

def scan_moduls(path, file_ext='.py'):
    '''生成插件清单'''
    pocs = []
    if os.path.isfile(path):
        m = re.search(r'(?:\\|/)([^/]+)/(DSO[\-_]\d+\{})$'.format(file_ext), path, re.I)
        if m:
            pocs.append(get_poc_attr_dict(
                m.group(1), m.group(2), path))
    else:
        for root, dirs, files in os.walk(path):
            if (root == path):
                continue
            # 获取模块名称
            module = root.replace(path + os.sep, '')
            for name in files:
                # 过滤除py以外的文件
                if (os.path.splitext(name)[1] == file_ext):
                    pocs.append(get_poc_attr_dict(
                        module, name, os.path.join(root, name)))
    return pocs


def get_poc_attr_dict(module, file_name, path):
    '''获取POC的所有属性，返回字典'''
    attrs = {}
    class_inst = get_poc_class(path, file_name)
    attrs['md5'] = calc_file_md5(path)
    attrs['module'] = unicode(module, 'utf-8', 'ignore')
    attrs['file_name'] = unicode(file_name, 'utf-8', 'ignore')
    attrs['path'] = unicode(path, 'utf-8', 'ignore')
    attrs['poc_name'] = unicode(class_inst.name, 'utf-8', 'ignore')
    attrs['vulID'] = unicode(class_inst.vulID, 'utf-8', 'ignore')
    attrs['version'] = class_inst.version
    attrs['severity'] = unicode(class_inst.severity, 'utf-8', 'ignore')
    attrs['author'] = unicode(class_inst.author, 'utf-8', 'ignore')
    attrs['vulDate'] = class_inst.vulDate
    attrs['createDate'] = class_inst.createDate
    attrs['updateDate'] = class_inst.updateDate
    attrs['appPowerLink'] = class_inst.appPowerLink.strip()
    attrs['appName'] = unicode(class_inst.appName.strip(), 'utf-8', 'ignore')
    attrs['appVersion'] = unicode(class_inst.appVersion.strip(), 'utf-8', 'ignore')
    attrs['vulType'] = unicode(class_inst.vulType.strip(), 'utf-8', 'ignore')
    attrs['desc'] = unicode(class_inst.desc.strip(), 'utf-8', 'ignore')
    attrs['samples'] = class_inst.samples
    attrs['cve'] = unicode(class_inst.cveID, 'utf-8', 'ignore') if hasattr(class_inst, 'cveID') else u''
    attrs['cnvd'] = unicode(class_inst.cnvdID, 'utf-8', 'ignore') if hasattr(class_inst, 'cnvdID') else u''
    attrs['cnnvd'] = unicode(class_inst.cnnvdID, 'utf-8', 'ignore') if hasattr(class_inst, 'cnnvdID') else u''
    attrs['bugtraq'] = unicode(class_inst.bidID, 'utf-8', 'ignore') if hasattr(class_inst, 'bidID') else u''
    attrs['edb'] = unicode(class_inst.edbID, 'utf-8', 'ignore') if hasattr(class_inst, 'edbID') else u''
    attrs['solution'] = unicode(class_inst.solution.strip(), 'utf-8', 'ignore') if hasattr(class_inst, 'solution') else u''
    attrs['taskType'] = unicode(class_inst.taskType.strip(), 'utf-8', 'ignore') if hasattr(class_inst, 'taskType') else u''
    
    # 根据关联ID生成参考链接
    refers = class_inst.references
    attrs['references'] = []
    for _ in refers:
        if len(_.strip()) > 0:
            attrs['references'].append(_)
    
    dso_url = 'https://poc.shuziguanxing.com/issue/info/{}'.format(attrs['vulID'][4:])
    if dso_url not in attrs['references']:
        attrs['references'].insert(0, dso_url)

    for _ in attrs['cve'].replace(';', ',').replace('/', ',').replace(' ', ',').split(','):
        if _.find('CVE-') != -1:
            cve_url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={}'.format(_)
            for url in attrs['references']:
                if 'cve.mitre.org' in url.lower() :
                    attrs['references'].remove(url)
            attrs['references'].append(cve_url)

    for _ in attrs['cnvd'].replace(';', ',').replace('/', ',').replace(' ', ',').split(','):
        if _.find('CNVD-') != -1:
            cve_url = 'https://www.cnvd.org.cn/flaw/show/{}'.format(_)
            for url in attrs['references']:
                if 'www.cnvd.org.cn' in url.lower() :
                    attrs['references'].remove(url)
            attrs['references'].append(cve_url)

    for _ in attrs['cnnvd'].replace(';', ',').replace('/', ',').replace(' ', ',').split(','):
        if _.find('CNNVD-') != -1:
            cve_url = 'http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD={}'.format(_)
            for url in attrs['references']:
                if 'www.cnnvd.org.cn' in url.lower() :
                    attrs['references'].remove(url)
            attrs['references'].append(cve_url)

    for _ in attrs['bugtraq'].replace(';', ',').replace('/', ',').replace(' ', ',').split(','):
        if _.strip() != '':
            cve_url = 'https://www.securityfocus.com/bid/{}'.format(_)
            for url in attrs['references']:
                if 'www.securityfocus.com' in url.lower() :
                    attrs['references'].remove(url)
            attrs['references'].append(cve_url)

    for _ in attrs['edb'].replace(';', ',').replace('/', ',').replace(' ', ',').split(','):
        if _.strip() != '':
            cve_url = 'https://www.exploit-db.com/exploits/{}'.format(_)
            for url in attrs['references']:
                if 'www.exploit-db.com' in url.lower() :
                    attrs['references'].remove(url)
            attrs['references'].append(cve_url)
    
    return attrs

def get_poc_class(path, file):
    '''获取POC中的TestPOC类'''
    file_name = os.path.splitext(file)[0]
    if file.endswith('.so') or file.endswith('.pyd'):
        module_path = os.path.split(path)[0]
        if 'modules' in sys.path[1]:
            sys.path[1] = module_path
        else:
            sys.path.insert(1, module_path)
        py_mod = __import__(file_name)
    else:
        py_mod = imp.load_source(file_name, path)
    return getattr(py_mod, 'TestPOC')()

def remove_duplicates(path):
    '''删除others目录下与其它目录重复的插件'''
    dirs = os.listdir(path)
    if 'others' in dirs:
        dirs.remove('others')
        for d in dirs:
            if os.path.isfile(os.path.join(path, d)):
                path_file = '{}/others/{}'.format(path, d)
                if os.path.exists(path_file):
                    os.remove(path_file)
            else:
                for file in os.listdir(path+d):
                    path_file = '{}/others/{}'.format(path, file)
                    if os.path.exists(path_file):
                        os.remove(path_file)
