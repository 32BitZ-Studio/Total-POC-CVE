#!/usr/bin/env python

"""
 * CVE-2012-5321
 * CVE-2012-5321 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */


"""


def writedata(output, data):
    with open(output, 'a') as file:
        file.write(data)
