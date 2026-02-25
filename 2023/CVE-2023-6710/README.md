# CVE-2023-6710 Exploit POC
Explore the depths of CVE-2023-6710 with metasploit and our comprehensive Proof of Concept (PoC). This CVE, identified as a potential security vulnerability, has been meticulously examined to demonstrate its impact and provide a hands-on understanding of the associated risks.

# Installation
- git clone https://github.com/DedSec-47/Metasploit-Exploits-CVE-2023-6710.git 
- cd Metasploit-Exploits-CVE-2023-6710
- sudo mv mod_cluster_xss.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/mod_cluster_stored_xss.rb


# Usage
- use auxiliary/scanner/mod_cluster_stored_xss
- set rhosts https://www.example.com
- set targeturi /cluster-manager
- set rport 443
- set ssl true
- exploit

# Disclaimer
This script is provided solely for educational and research purposes. Please use it responsibly and only on systems for which you have explicit permission to test. Unauthorized or malicious use of this script could lead to legal consequences and ethical concerns. Ensure that you adhere to ethical guidelines and respect the privacy and security of others.



