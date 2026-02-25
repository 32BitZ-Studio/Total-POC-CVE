# Joomla! CVE-2023-23752 - Unauthenticated Information Disclosure PoC

## Description

This repository contains a Proof of Concept (PoC) exploit for CVE-2023-23752, a vulnerability in Joomla! that allows unauthenticated information disclosure. This vulnerability can expose sensitive information, including database credentials, configuration files, and more, to unauthenticated users.

## PoC

You can watch my PoC on this CVE here:

https://www.youtube.com/watch?v=vf_d0AWd7T8

## Details

- **CVE:** CVE-2023-23752
- **Vulnerability Type:** Information Disclosure
- **Affected Version:** Joomla! 4.2.8

## Usage

1. **Clone the repository:**
    ```
    git clone https://github.com/0x0jr/HTB-Devvortex-CVE-2023-2375-PoC.git
    ```

2. **Install dependencies:**
    ```
    pip install requests
    ```

3. **Run the PoC:**
    ```
    python3 exploit.py <target_url>
    ```

    Replace `<target_url>` with the URL of the target Joomla! instance.

## Example

```
python3 exploit.py http://dev.devvortex.htb/
```
