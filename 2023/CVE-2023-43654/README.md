# CVE-2023-43654
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/OligoCyberSecurity/ShellTorchChecker/assets/8081679/e35ee9a8-425c-47d1-b246-13e19e450860">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/OligoCyberSecurity/ShellTorchChecker/assets/8081679/a2d9f351-3e69-4d67-b3d1-c0a982cb89cf">
  <img height=130px  alt="ShellTorch Logo" src="https://github.com/OligoCyberSecurity/ShellTorchChecker/assets/8081679/a2d9f351-3e69-4d67-b3d1-c0a982cb89cf">
</picture>

<b>ShellTorch</b> is a chain of <a href="https://www.oligo.security/shelltorch">3 Critical Vulnerabilities</a> in PyTorch TorchServe - the default inference server of PyTorch.
This is an End-to-End POC for an [`SSRF`](https://github.com/pytorch/serve/security/advisories/GHSA-8fxr-qfr9-p34w) vulnerability which leads to [`Arbitrary Remote Code Execution`](https://github.com/pytorch/serve/security/advisories/GHSA-4mqg-h5jf-j9m7) from the network<br>
<br>


### 1. Run [`TorchServe 0.8.1`](https://github.com/pytorch/serve/tree/release_0.8.1/docker#start-a-container-with-a-torchserve-image)

```shell
docker run -d --rm -it -p 8080:8080 -p 8081:8081 -p 8082:8082 -p 7070:7070 -p 7071:7071 --name shelltorch-demo pytorch/torchserve:0.8.1-cpu

docker logs -f shelltorch-demo
```

### 2. Run the [`ShellTorch-Checker`](https://github.com/OligoCyberSecurity/ShellTorchChecker/) script
This tool is used to check if a given deployment is vulnerable to CVE-2023-43654.
```shell
bash <(curl https://raw.githubusercontent.com/OligoCyberSecurity/ShellTorchChecker/main/ShellTorchChecker.sh) "127.0.0.1"
```
Output:
```shell
 _____  _    _ ______ _      _   _______ ____  _____   _____ _    _
/ ____ | |  | |  ____| |    | | |__   __/ __ \|  __ \ / ____| |  | |
| (___ | |__| | |__  | |    | |    | | | |  | | |__) | |    | |__| |
\___  \|  __  |  __| | |    | |    | | | |  | |  _  /| |    |  __  |
____)  | |  | | |____| |____| |____| | | |__| | | \ \| |____| |  | |
|_____/|_|  |_|______|______|______|_|  \____/|_|  \_\______|_|  |_|


This script checks for TorchServe CVE-2023-43654
The vulnerability was found by the Oligo research team and allows for No-Auth RCE
For more details please see our full report at https://www.oligo.security/blog/shelltorch-torchserve-ssrf-vulnerability-cve-2023-43654

Disclaimer:
By using this tool, you acknowledge and agree that it is provided "as is" without
warranty of any kind, either express or implied. Oligo and any contributors shall not be held
liable for any direct, indirect, incidental, or consequential damages or false results arising
out of the use, misuse, or reliance on this tool.
You are solely responsible for understanding the output and implications of using this tool
and for any actions taken based on its findings.
Use at your own risk.
...........................................
By continuing running this script I agree that I have read the disclamer and have agreed to it.
Press any key to start scanning, Press Ctrl+C to exit.

torchserve is not running locally.
Scan Results:
  [-] Checking Management Interface API Misconfiguration (port 8081)
    [X] 127.0.0.1:8081 is open to remote connections
  [-] Checking CVE-2023-43654 Remote Server-Side Request Forgery (SSRF)
    [X] Vulnerable to CVE-2023-43654 SSRF file download

Recomendations:
  [-] To resolve Management Interface API Misconfiguration:
      Change "management_address" in config.properties from 0.0.0.0 to 127.0.0.1
      example:
        management_address: http://127.0.0.1:8081
  [-] To resolve CVE-2023-43654 SSRF file download:
      Configure specific urls in the "allowed_urls" field of config.properties.
      example:
        allowed_urls=https://s3.amazonaws.com/.*,https://torchserve.pytorch.org/.*
```

### 3. Cleanup
```shell 
docker kill shelltorch-demo && rm -rf model-store
```

# References:
* <a href="https://www.oligo.security/shelltorch">ShellTorch Blog</a>
* <a href="https://github.com/OligoCyberSecurity/ShellTorchChecker/">ShellTorch-Checker</a>
* <a href="https://github.com/pytorch/serve/tree/release_0.8.1/docker#start-a-container-with-a-torchserve-image">GitHub</a> TorchServe Documentation
* <a href="https://hub.docker.com/layers/pytorch/torchserve/0.8.1-cpu/images/sha256-4135174332c7b92505659b4b38688e9c92576b3679a1358dfdb0bdece88e7491?context=explore">Docker Hub</a> Image
