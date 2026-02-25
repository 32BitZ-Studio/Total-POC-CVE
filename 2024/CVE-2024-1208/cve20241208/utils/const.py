#!/usr/bin/env python

"""
 * CVE-2024-1208
 * CVE-2024-1208 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */


"""


class Data:
    blog = 'https://blogs.cappriciosec.com/blog/174/CVE-2024-1208'
    api = 'https://api.cappriciosec.com/Telegram/cappriciosecbot.php'
    config_path = '~/.config/cappriciosec-tools/cappriciosec.yaml'
    payloadurl = 'https://raw.githubusercontent.com/Cappricio-Securities/PayloadAllTheThings/main/CVE-2024-1208.txt'
    bugname = "LearnDash LMS < 4.10.3 - Sensitive Information Exposure"

    rheaders = {
        "Tool-Name": "CVE-2024-1208",
        "Developed-by": "cappriciosec.com",
        "Contact-us": "contact@cappriciosec.com"
    }


class Colors:
    RED = '\x1b[31;1m'
    BLUE = '\x1b[34;1m'
    GREEN = '\x1b[32;1m'
    RESET = '\x1b[0m'
    MAGENTA = '\x1b[35;1m'
