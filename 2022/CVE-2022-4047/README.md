# WooRefer | CVE-2022-4047 - Return Refund and Exchange For WooCommerce
Automatic Mass Tool for check and exploiting vulnerability in CVE-2022-4047 - Return Refund and Exchange For WooCommerce < 4.0.9 - Unauthenticated Arbitrary File Upload (Mass PHP File Upload)<br><br>
<img src="https://github.com/im-hanzou/WooRefer/blob/main/image/woorefer.png" width=600></img><br>
- Using GNU Parallel. You must have parallel for run this tool.<br>
- <b>If you found error like "$'\r': command not found" just do "dos2unix woorefer.sh"</b>
# Install Parallel
- Linux : <code>apt-get install parallel -y</code><br>
- Windows : You can install WSL (windows subsystem linux) then do install like linux<br>if you want use windows (no wsl), install <a href="https://git-scm.com/download/win">GitBash</a> then do this command for install parallel: <br>
[#] <code>curl pi.dk/3/ > install.sh </code><br>[#] <code>sha1sum install.sh | grep 12345678 </code><br>[#] <code>md5sum install.sh </code><br>[#] <code>sha512sum install.sh </code><br>[#] <code>bash install.sh</code><br>
# How To Use
- <b>Make sure you already install Parallel!</b> Then do:
- [#] <code>git clone https://github.com/im-hanzou/WooRefer.git</code>
- [#] <code>cd WooRefer</code>
- [#] For Linux or WSL: <code>bash woorefer.sh list.txt thread</code>
- [#] For Gitbash: <code>TMPDIR=/tmp bash woorefer.sh list.txt thread</code>
# Reference
- https://nvd.nist.gov/vuln/detail/CVE-2022-4047
- https://wpscan.com/vulnerability/8965a87c-5fe5-4b39-88f3-e00966ca1d94
- https://github.com/advisories/GHSA-3j85-6864-55p3
# Disclaimer:
- <b><i>This tool is for educational purposes only. Use it responsibly and with proper authorization. The author is not responsible for any misuse.</b></i>
