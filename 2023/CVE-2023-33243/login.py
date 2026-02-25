#!/usr/bin/env python3

########################################
#                                      #
#  RedTeam Pentesting GmbH             #
#  kontakt@redteam-pentesting.de       #
#  https://www.redteam-pentesting.de/  #
#                                      #
########################################

import click
import hashlib
import re
import requests
import typing


def get_values_from_session(url, session) -> typing.Tuple[str, str]:
    k, bk = "", ""
    response_content = session.get(f"{url}/jsp/index.jsp").text
    k_result = re.search("\sk : '([^']+)'", response_content)
    bk_result = re.search("\sbk : '([^']+)'", response_content)
    if k_result != None:
        k = k_result.group(1)
    if bk_result != None:
        bk = bk_result.group(1)
    return k, bk


def web_login(url, login, pwhash, session) -> bool:
    version, nonce = get_values_from_session(url, session)
    if version == "" or nonce == "":
        print("Web Login failed: Nonce and version hash can not be retrieved.")
        return
    value = login + version + nonce + pwhash
    secret = hashlib.sha512(value.encode("utf-8")).hexdigest()
    data = {
        "forward": "",
        "autologin": "false",
        "secret": f"{login}:{secret}",
        "ack": version,
    }
    login_request = session.post(
        f"{url}/login",
        data=data,
        allow_redirects=False,
        headers={"Referer": f"{url}/jsp/index.jsp"},
    )
    response_headers = login_request.headers
    if "Set-Cookie" in response_headers:
        session_id = response_headers["Set-Cookie"].split("=")[1].split(";")[0]
        print(f"Session ID: {session_id}")
        return True
    else:
        print("Invalid login data")
        return False


def get_nonce_from_api(url, session) -> str:
    response_content = session.get(f"{url}/rest/login").json()
    return response_content["nonce"] if "nonce" in response_content else ""


def rest_login(url, login, pwhash, session):
    nonce = get_nonce_from_api(url, session)
    if nonce == "":
        print("REST Login failed: Nonce can not be retrieved.")
        return
    value = login + nonce + pwhash
    secret = hashlib.sha512(value.encode("utf-8")).hexdigest()
    data = {"loginType": "Internal", "nonce": nonce, "secret": f"{login}:{secret}"}
    login_request = session.post(
        f"{url}/rest/login",
        json=data,
        headers={"Content-Type": "application/json", "X-Version": "2"},
    )
    response_data = login_request.json()
    token = response_data["token"] if "token" in response_data else "none"
    print(f"REST API Token: {token}")


@click.command()
@click.option('--url', help='Target System URL', required=True)
@click.option('--login', help='Login ID', required=True)
@click.option('--pwhash', help='Password Hash', required=True)
def login(url, login, pwhash):
    session = requests.session()
    stripped_url = url.rstrip("/")
    result = web_login(stripped_url, login, pwhash, session)
    if result:
        rest_login(stripped_url, login, pwhash, session)


if __name__ == "__main__":
    login()
