#!/usr/bin/env python

"""
 * CVE-2018-8033
 * CVE-2018-8033 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */
"""
import requests
from cve20188033.utils import const
from cve20188033.utils import configure


def sendmessage(vul):

    data = {"Tname": "CVE-2018-8033", "chatid": configure.get_chatid(), "data": vul,
            "Blog": const.Data.blog, "bugname": const.Data.bugname, "Priority": "Critical"}

    headers = {
        "Content-Type": "application/json",
    }
    try:
        response = requests.put(const.Data.api, json=data, headers=headers)
    except:
        print("Bot Error")
