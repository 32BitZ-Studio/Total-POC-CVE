# Claude Code: MCP Tool Confirmation Prompt Misrepresentation

![Status](https://img.shields.io/badge/Status-Unpatched--v2.1.63-red)
![CWE](https://img.shields.io/badge/CWE-451-orange)
![Security](https://img.shields.io/badge/Focus-AI%20Agent%20Security-blue)

A professional Proof-of-Concept (PoC) demonstrating a critical UI/UX flaw in Anthropic's Claude Code. This vulnerability allows a malicious MCP server to mislead users into approving arbitrary command execution by misrepresenting tool parameters in confirmation prompts.

## 🛡️ Technical Summary
Claude Code trusts the description and metadata provided by an MCP server to generate user-facing confirmation prompts. An attacker-controlled server can provide a benign description (e.g., "Read a file") while the underlying execution logic triggers a reverse shell or unauthorized file writes.



## 🚀 Key Features
* Informed Consent Bypass: Users approve a "Safe" action while the server executes "Malicious" code.
* Modified Alert: Includes a built-in check to prevent execution without proper IP configuration.
* Research Focused: Differentiates from existing CVEs (CVE-2025-59536) by focusing on post-consent execution.

## 🛠️ Installation & Setup
```bash
# Clone the research repository
git clone [https://github.com/Rohitberiwala/Claude-Code-MCP-Injection](https://github.com/Rohitberiwala/Claude-Code-MCP-Injection)
cd Claude-Code-MCP-Injection

# Edit the script to add your listener IP
nano exploit.py

# Run the PoC generator
python3 exploit.py
