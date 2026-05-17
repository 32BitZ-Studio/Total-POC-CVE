#!/usr/bin/env python3
import asyncio
import json
import os

from slixmpp import ClientXMPP


XMPP_USER = os.environ.get("AHENK_USER", "pardus-ct-2@im.liderahenk.org")
XMPP_PASS = os.environ.get(
    "AHENK_PASS", "e0c5a52e-36c2-31fc-ad0b-e9ceabbf3401"
)
XMPP_HOST = os.environ.get("AHENK_HOST", "192.168.100.13")
XMPP_PORT = int(os.environ.get("AHENK_PORT", "5222"))
TARGET_JID = os.environ.get("AHENK_TARGET", "pardus-ct-1@im.liderahenk.org")
COMMAND = os.environ.get("AHENK_COMMAND", "touch /tmp/ct2_to_ct1_poc; false")


class Sender(ClientXMPP):
    def __init__(self):
        super().__init__(XMPP_USER, XMPP_PASS)
        self.enable_starttls = False
        self.enable_direct_tls = False
        self.enable_plaintext = True
        self.register_plugin("feature_mechanisms")
        self["feature_mechanisms"].unencrypted_plain = True
        self.add_event_handler("session_start", self.session_start)
        self.add_event_handler("disconnected", self.on_disconnected)

    async def session_start(self, event):
        print(f"SESSION_START=1 user={XMPP_USER}", flush=True)
        self.send_presence()
        await self.get_roster()
        payload = {
            "type": "EXECUTE_SCRIPT",
            "command": COMMAND,
        }
        self.send_message(mto=TARGET_JID, mbody=json.dumps(payload), mtype="normal")
        print(f"MESSAGE_SENT=1 target={TARGET_JID}", flush=True)
        await asyncio.sleep(1)
        self.disconnect()

    def on_disconnected(self, event):
        asyncio.get_event_loop().stop()


def main():
    print(f"XMPP_HOST={XMPP_HOST}", flush=True)
    print(f"XMPP_PORT={XMPP_PORT}", flush=True)
    print(f"TARGET_JID={TARGET_JID}", flush=True)
    print(f"COMMAND={COMMAND}", flush=True)
    xmpp = Sender()
    xmpp.connect(host=XMPP_HOST, port=XMPP_PORT)
    loop = xmpp.loop
    loop.call_later(10, xmpp.disconnect)
    loop.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
