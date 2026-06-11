#!/usr/bin/env python

"""
 * CVE-2019-12616
 * CVE-2019-12616 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */
 
"""
from includes import bot
from utils import configure
import json
import requests
import urllib.parse
import re
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote
from includes import writefile
from utils import const
from urllib.parse import urlparse


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def compare_versions(version1, version2):
    version1 = [int(v) for v in version1.split('.')]
    version2 = [int(v) for v in version2.split('.')]
    return version1 < version2

def cvescan(url, output):
    try:
        with requests.Session() as session:
            payreq = session.get(const.Data.payloadurl)
            for endpoint in payreq.text.splitlines():
                encode = quote(endpoint)
                if url.endswith('/'):
                    url = url[:-1]
                fullurl = f'{url}/{endpoint}'

                try:
                    response = session.get(
                        fullurl, verify=False, headers=const.Data.rheaders, allow_redirects=True, timeout=5)
                    print(f'Checking ===> {fullurl}')
                    version_match = re.search(r'\?v=([0-9.]+)', response.text)
                    if version_match is not None:
                        global version
                        version = version_match.group(1)
                    if response.status_code == 401 or response.status_code == 200 and 'phpmyadmin.net' in response.text or 'phpMyAdmin' in response.text and version is not None and compare_versions(version, '4.9.0'):
                        outputprint = (
                            f"\n{const.Colors.RED}💸[Vulnerable]{const.Colors.RESET} ======> "
                            f"{const.Colors.BLUE}{url}{const.Colors.RESET} \n"
                            f"{const.Colors.MAGENTA}📸PoC-Url->{const.Colors.BLUE}${const.Colors.RESET} {fullurl}\n\n\n")

                        print(outputprint)
                        if configure.check_id() == "Exist":
                            bot.sendmessage(fullurl)
                        if output is not None:
                            writefile.writedata(
                                output, str(f'{fullurl}\n'))
                        break

                except requests.exceptions.RequestException as e:
                    print(
                        f'{const.Colors.MAGENTA}Invalid Domain ->{const.Colors.BLUE}${const.Colors.RESET} {fullurl}: {e}')
    except requests.exceptions.RequestException as e:
        print(f"Check Network Connection: {e}")
