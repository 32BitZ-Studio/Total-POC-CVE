#!/usr/bin/env python

"""
 * CVE-2021-42063
 * CVE-2021-42063 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */
"""
import requests
from cve202142063.utils import const
from cve202142063.utils import configure


def sendmessage(vul):

    data = {"Tname": "CVE-2021-42063", "chatid": configure.get_chatid(), "data": vul,
            "Blog": const.Data.blog, "bugname": const.Data.bugname, "Priority": "Medium"}

    headers = {
        "Content-Type": "application/json",
    }
    try:
        response = requests.put(const.Data.api, json=data, headers=headers)
    except:
        print("Bot Error")
