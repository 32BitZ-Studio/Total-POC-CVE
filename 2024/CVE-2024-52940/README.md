# AnyDesk IP Leak Vulnerability CVE-2024-52940


## 🎤 README Translation
- [English](README.md)
- [Deutsch](README.de.md)
- [فارسی](README.fa.md)

## 📸 Screenshot

 <p align="center"><img src="abdal-anydesk-remote-ip-detector-proof.gif?raw=true"></p>

## 🎥 Proof of Concept Videos

To see the **AnyDesk IP Leak Vulnerability** in action, you can download the PoC demonstration videos below:

- [📥 Download Proof 01](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/raw/main/abdal-anydesk-remote-ip-detector-proof.mp4)
- [📥 Download Proof 02](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/raw/main/abdal-anydesk-remote-ip-detector-proof-2.mp4)
- Recommended - [📥 Download Proof 03](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/raw/main/abdal-anydesk-remote-ip-detector-proof-3.mp4)

These videos showcase how the vulnerability operates, illustrating the steps and impact on IP address privacy.

## 💎 Introduction
The **Abdal AnyDesk Remote IP Detector** is a Proof-of-Concept (PoC) tool that exploits a **Zero-Day vulnerability** discovered on **October 27, 2024**, in AnyDesk’s "Allow Direct Connections" feature. When this option is enabled, and the connection port is set to 7070 on the attacker's system only, it allows an attacker to retrieve the public IP address of a target using only the AnyDesk ID, without any configuration changes on the target system. Additionally, if both systems are on the same network, the attacker can also obtain the target’s private IP address.

## 💀 Vulnerability Overview
This **Zero-Day vulnerability** in AnyDesk's "Allow Direct Connections" feature exposes sensitive IP information of the target. Attackers can exploit this flaw to retrieve the public IP address, and, in specific cases, the private IP address of the target system. This vulnerability poses significant privacy risks, particularly when security configurations are insufficiently protected in remote access tools.

When the Allow Direct Connections option is enabled on the attacker’s system, AnyDesk inadvertently exposes the target’s public IP address in network traffic. This IP address can be easily identified through network sniffing on the attacker’s system. If both systems are on the same local network, the target’s private IP address may also be accessible. The image below demonstrates the network traffic capture using the Abdal Sniffer tool, highlighting how this information is exposed.

<p align="center"><img src="vulnerability-overview-01.png?raw=true"></p>

### 🔍 CVE Details
This vulnerability has been officially registered as **CVE-2024-52940**.  
It was submitted and registered under the name of **Ebrahim Shafiei (EbraSha)** by **NIST** (National Institute of Standards and Technology), **Tenable**, and **MITRE**, a U.S. government advisory organization in scientific and technical domains.

For more information, visit:
- [CVE-2024-52940 page on NVD (NIST)](https://nvd.nist.gov/vuln/detail/CVE-2024-52940)
- [Tenable CVE Page](https://www.tenable.com/cve/CVE-2024-52940)
- [MITRE CVE Page](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-52940)


## ✨ Features
* Retrieves public IP address of a remote system when AnyDesk ID is known.
* Private IP detection within local network connections.
* Quick setup and straightforward PoC execution.
* No complex dependencies;
 

## 🛠️ Development Environment Setup
- **.NET 6**
- **Visual Studio 2022**
 

## 🔥 Requirements
There are no specific prerequisites needed to run this PoC.

## 📥 Download
To download the executable versions of this PoC, please visit the official Releases page on GitHub. This will allow you to obtain the compiled version ready for use:

- [Download Executable PoC Versions from GitHub](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/releases)

 

## 📦 Setup and Usage
1. Enable Direct Connections in AnyDesk: Open AnyDesk on your system, go to Settings > Connection, then enable the option Allow direct connections. Set the connection port to 7070.
2. Launch the PoC Tool: Run the Abdal AnyDesk Remote IP Detector tool.
3. Enter Target AnyDesk ID: In the AnyDesk application on your system, input the AnyDesk ID of the target system.
4. IP Retrieval via Network Traffic Monitoring: After entering the target's AnyDesk ID in your AnyDesk, the PoC tool automatically listens to the network traffic on your system to detect and display the public IP address of the target. If both systems are within the same local network, the tool will also display the target's private IP address.


## 😎 Expected Output
The tool will output:

* The public IP address of the remote system.
* The private IP address if the two systems are within the same local network.

## 🛑 Affected Versions

This vulnerability affects **AnyDesk version 8.1.0 and below**. As of now, there is no fixed version released to address this issue.

## ✅ Mitigation
Unfortunately, there is currently no user-side fix for this vulnerability. To fully address this issue, an update or patch from AnyDesk’s development team is required.

## 🎖️ Credit
- **Bug Discovery and PoC Developer**: Ebrahim Shafiei (EbraSha)
- [Profile on Linkedin](https://www.linkedin.com/in/profshafiei/)

 
## ❤️ Donation
If you find this project helpful and would like to support further development, please consider making a donation:
- [Donate Here](https://ebrasha.com/abdal-donation)

## 🤵 Programmer
Handcrafted with Passion by **Ebrahim Shafiei (EbraSha)**
- **E-Mail**: Prof.Shafiei@Gmail.com
- **Telegram**: [@ProfShafiei](https://t.me/ProfShafiei)

## ☠️ Reporting Issues
If you encounter any issues or have configuration problems, please reach out via email at Prof.Shafiei@Gmail.com. You can also report issues on GitLab or GitHub.

## ⚠️  Legal Disclaimer
This Proof of Concept (PoC) is provided for educational purposes only. Unauthorized use of this code on systems you do not own or have explicit permission to test is illegal and unethical. By using this PoC, you agree to take full responsibility for any misuse or damage that may result. The author disclaims all liability for actions taken based on the information provided in this repository. Always ensure you have proper authorization before conducting any security testing.