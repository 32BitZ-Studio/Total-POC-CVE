# EVCer | CVE-2023-0159 - Extensive VC Addons for WPBakery page builder
Automatic Mass Tool for checking vulnerability in CVE-2023-0159 - Extensive VC Addons for WPBakery page builder < 1.9.1 - Unauthenticated LFI<br>Using GNU Parallel. You must have parallel for running this tool.<br>
- <b>If you found error like "$'\r': command not found" just do "dos2unix evcer.sh"</b>
# Install Parallel
- Linux : <code>apt-get install parallel -y</code><br>
- Windows : You can install WSL (windows subsystem linux) then do install like linux<br>if you want use windows (no wsl), install <a href="https://git-scm.com/download/win">GitBash</a> then do this command for install parallel: <br>
[#] <code>curl pi.dk/3/ > install.sh </code><br>[#] <code>sha1sum install.sh | grep 12345678 </code><br>[#] <code>md5sum install.sh </code><br>[#] <code>sha512sum install.sh </code><br>[#] <code>bash install.sh</code><br>
# How To Use
- [#] <code>bash evcer.sh yourlist.txt thread</code>
# Reference
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0159
- https://wpscan.com/vulnerability/239ea870-66e5-4754-952e-74d4dd60b809
- https://github.com/advisories/GHSA-c4h9-8c9r-v3m8
