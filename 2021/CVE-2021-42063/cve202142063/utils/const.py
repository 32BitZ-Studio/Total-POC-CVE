#!/usr/bin/env python

"""
 * CVE-2021-42063
 * CVE-2021-42063 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */


"""


class Data:
    blog = 'https://blogs.cappriciosec.com/cve/140/CVE-2021-42063%20-%20A%20Look%20at%20Microsoft%20Exchange%20Server%20Code%20Execution%20Vulnerability'
    api = 'https://api.cappriciosec.com/Telegram/cappriciosecbot.php'
    config_path = '~/.config/cappriciosec-tools/cappriciosec.yaml'
    payloadurl = 'https://raw.githubusercontent.com/Cappricio-Securities/PayloadAllTheThings/main/CVE-2021-42063.txt'
    bugname = 'GET Based R-XSS'
    rheaders = {
        "User-Agent": "cappriciosec.com",
        "Tool-Name": "CVE-2021-42063",
        "Developed-by": "cappriciosec.com",
        "Contact-us": "contact@cappriciosec.com"
    }


class Colors:
    RED = '\x1b[31;1m'
    BLUE = '\x1b[34;1m'
    GREEN = '\x1b[32;1m'
    RESET = '\x1b[0m'
    MAGENTA = '\x1b[35;1m'
