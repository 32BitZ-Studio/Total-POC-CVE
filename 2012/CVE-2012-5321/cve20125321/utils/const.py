#!/usr/bin/env python

"""
 * CVE-2012-5321
 * CVE-2012-5321 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */


"""


class Data:
    blog = 'https://blogs.cappriciosec.com/cve/196/TikiWiki%20Paradise%20Lost%20-%20The%20RCE%20Vulnerability%20(CVE-2012-5321)%20and%20Charting%20a%20Course%20for%20Secure%20Collaboration'
    api = 'https://api.cappriciosec.com/Telegram/cappriciosecbot.php'
    config_path = '~/.config/cappriciosec-tools/cappriciosec.yaml'
    payloadurl = 'https://raw.githubusercontent.com/Cappricio-Securities/PayloadAllTheThings/main/CVE-2012-5321.txt'
    bugname = "TikiWiki CMS Groupware v8.3 - Open Redirect"

    rheaders = {
        "Tool-Name": "CVE-2012-5321",
        "Developed-by": "cappriciosec.com",
        "Contact-us": "contact@cappriciosec.com"
    }


class Colors:
    RED = '\x1b[31;1m'
    BLUE = '\x1b[34;1m'
    GREEN = '\x1b[32;1m'
    RESET = '\x1b[0m'
    MAGENTA = '\x1b[35;1m'
