# CVE-2018-19987 (D-Link OS command injection) analysis [![Twitter URL](https://img.shields.io/twitter/url?style=social&url=https://github.com/nahueldsanchez/blogpost_cve-2018-19987-analysis)](https://twitter.com/intent/tweet?text=https://github.com/nahueldsanchez/blogpost_cve-2018-19987-analysis)

[![Twitter Follow](https://img.shields.io/twitter/follow/nahueldsanchez_?color=1DA1F2&logo=twitter&style=for-the-badge)](https://twitter.com/nahueldsanchez_?s=20)

Hello there!

In this short blog post I'll break down a quick analysis that I performed to better understand the details behind CVE-2018-19987. At the beginning I went after this CVE because I thought that there wasn't any public information or exploit. Shortly after doing a first analysis, I found two public PoCs on GitHub that you can find [here](https://github.com/ceballosm/scratchpad/blob/28da8dbceffe26cccbdb5124227de9201948596d/CVE-2018-19987.rb) and [here](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990#cve-2018-19987---hnap1setaccesspointmode).

As I had already done most of the work and hadn't found a complete analysis, I decided to write the blog post anyways.


I hope you enjoy it!

*Update:* Well.. after googling while I was stuck with this blog post I found the following article that describes a very similar vulnerability (CVE-2018-19986) in the D-Link DIR-818. [Router vulnerability analysis series (5): CVE-2018-19986 DIR-818LW&828 command injection vulnerability analysis and reproduction](https://translate.google.com/translate?hl=&sl=zh-CN&tl=en&u=https%3A%2F%2Fxz.aliyun.com%2Ft%2F5808) (Google translated) by Ogur1.

# CVE-2018-19987 Analysis

I started my analysis gathering all the information I could about the device:

- Consumer Name: D-Link DIR-822-US
- Product Page: https://us.dlink.com/en/products/dir-822-d-link-wifi-router-ac1200-dual-band
- Support Page(s): https://support.dlink.com/ProductInfo.aspx?m=DIR-822-US
- Model: DIR-822 Revision C (Other devices were affected)
- Affected firmware version: FW v3.01B02
- Affected firmware filename: DIR822C1_FW301WWb02.bin (md5sum: 1bff7ec8b4da0643f65b4d44c630e92b)
- Fixed firmware version: FW v3.13
- Fixed firmware filename: DIR822C1_FW313WWb01.bin (md5sum: aa16c7016f67be384e0784e439ce26d2)
- Firmware archive page: ftp://ftp2.dlink.com/PRODUCTS/DIR-822-US/REVC/

## Root cause analysis

>_Note: I performed all the analysis with firmware v3.01B02._

Public information for this vulnerability, available on [Mitre's page](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-19987), provided enough information to start:

```
D-Link DIR-822 Rev.B 202KRb06, DIR-822 Rev.C 3.10B06, DIR-860L Rev.B 2.03.B03, DIR-868L Rev.B 2.05B02, DIR-880L Rev.A 1.20B01_01_i3se_BETA, and DIR-890L Rev.A 1.21B02_BETA devices mishandle IsAccessPoint in /HNAP1/SetAccessPointMode. In the SetAccessPointMode.php source code, the IsAccessPoint parameter is saved in the ShellPath script file without any regex checking. After the script file is executed, the command injection occurs. A vulnerable /HNAP1/SetAccessPointMode XML message could have shell metacharacters in the IsAccessPoint element such as the `telnetd` string.
```

To begin the analysis I needed something to take a look at, so I proceeded to extract the router's FS.

```
binwalk -eM DIR822C1_FW301WWb02.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             DLOB firmware header, boot partition: "dev=/dev/mtdblock/1"
10380         0x288C          LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 4213444 bytes
1376372       0x150074        PackImg section delimiter tag, little endian size: 10505216 bytes; big endian size: 5021696 bytes
1376404       0x150094        Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 5019773 bytes, 2282 inodes, blocksize: 131072 bytes, created: 2016-03-18 09:35:31
```

As we can see Binwalk does detect a Linux file system. If we take a deeper look at the information we have, we can see that the advisory mentions the `/HNAP1` path. So, we can start looking at how the router handles these URLs.

### HNAP1 Requests handling

As explained in the excellent [/dev/tty0 blog post](http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/), these URLs at the end are handled by a binary called `cgibin`, located at `htdocs/cgibin`. But I wanted to better understand how this was configured and in the end it led me to have to understand how the HTTP server was configured to process requests. I proceeded to look for the `httpd.conf` file name, assuming that was used to configure the HTTP server, and found a file called `HTTP.php` under the `/etc/services/` folder, containing among other things the following interesting lines:

```php
$httpd_conf = "/var/run/httpd.conf";
fwrite("a",$START, "xmldbc -P /etc/services/HTTP/httpcfg.php > ".$httpd_conf."\n");
fwrite("a",$START, "event PREFWUPDATE add /etc/scripts/prefwupdate.sh\n");
fwrite("a",$START, "httpd -f ".$httpd_conf."\n");
fwrite("a",$START, "event HTTP.UP\n");
fwrite("a",$START, "exit 0\n");
```

I assumed that at some point this file is executed and writes the `/var/run/httpd.conf` file. To learn how the web server was configured, I proceeded to analyze the `/etc/services/HTTP/httpcfg.php` file (I only included the relevant parts):

```
	if ($hnap > 0)
	{
		echo
		"		Control".							"\n".
		"		{".									"\n".
		"			Alias /HNAP1".					"\n".
		"			Location /htdocs/HNAP1".		"\n".
		"			External".						"\n".
		"			{".								"\n".
		"				/usr/sbin/hnap { hnap }".	"\n".
		"			}".								"\n".
		"			IndexNames { index.hnap }".		"\n".
		"		}".									"\n";
	}
```

Now we have all the pieces! We can assume that the web server is configured to handle HTTP requests to `/HNAP1` using the `/usr/sbin/hnap`, and based on _/dev/tty0_ blogpost we know that it will be a link to the `htdocs/cgibin` binary.

The next step was to take a look at the `cgibin` binary to understand how it handled HNAP requests. In the following image we can see part of the decompiled `main` function where the path URL path passed to it is compared against different paths (such as session.cgi, authentication.cgi, captcha.cgi, to name a few) until `hnap` is found and our function `hnap_main` is called.

>_note: While analyzing the main function, I had some issues identifying the hnap string as Ghidra did not detect it as string during the initial analysis._

The next step was to understand what this function did. I'll provide only snippets of code for the relevant parts that will help to better understand what the function does, also I will complete other relevant parts with some pseudocode &mdash;I renamed some variables to clarify its purpose. 

```C
...
HTTP_SOAPACTION = getenv("HTTP_SOAPACTION");
REQUEST_METHOD = getenv("REQUEST_METHOD");
HNAP_AUTH = getenv("HTTP_HNAP_AUTH");
__haystack = getenv("HTTP_COOKIE");
pcVar1 = getenv("HTTP_REFERER");

...
if (HTTP_SOAPACTION != "") {
	if  (HTTP_SOAPACTION == GetDeviceSettings) {
		...
	} else {
		// These actions will occur during auth. Process
		if ("GetCAPTCHAsetting" in HTTP_SOAPACTION) {
			sess_generate_captcha();
		} else {
			if ("Login" in HTTP_SOAPACTION) {
				perform_login();
			}
			// We'll land here once auth.
			if (HNAP_AUTH != "") {
				if ("uid=" in HTTP_COOKIE){
					is_valid_auth = perform_auth_process()
					if (is_valid_auth) {
						if("logout" in HTTP_SOAPACTION){
							perform_logout();
						// If we are auth. and NOT trying to logout
						// the code will try to perform the action
						// we requested
						} else {
							// If we arrive here we win
							// interesting code below
							goto LAB_004141d4;
						}

					}
				}
			}
			// If we are not authenticated we can't do anything
			Return "You need proper authorization to use this resource"
		}
	}
} else {
	...
}

LAB_004141d4:
    hnap_action = get_hnap_operation(HTTP_SOAPACTION);
    if (HTTP_SOAPACTION != "") {
    	hnap_action_len = strlen(hnap_action);
	}
	snprintf(path_to_hnap_php_file,0x100,"%s/%s.php","/etc/templates/hnap/",hnap_action);
	if (!check_file_access(path_to_hnap_php_file)){
		return "HNAP ACTION DOES NOT EXIST (FAIL)"
	}
	if (REQUEST_METHOD == "POST") {

		// Here arguments for the PHP are extracted
		parse_request_and_extract_xml()
    
		if (hnap_action == "GetFirmwareStatus") {
        	system("sh /etc/events/checkfw.sh > /dev/console");
		}

		// Here the final arguments for the xmldbc_ephp are crafted
        snprintf(ARGS_FOR_XMLDBC_PHP,0x100,"%s%s.php\nShellPath=%s%s.sh\nPrivateKey=%s\n",
                 "/etc/templates/hnap/", hnap_action, &ShellPath, hnap_action, &PRIVATE_KEY);

		// PHP is executed (in our case SetAccessPointMode.php) and the shell
		// script is written to ShellPath 
        xmldbc_ephp(0,0,ARGS_FOR_XMLDBC_PHP,stdout);
        snprintf(hnap_action, 0x100, "%s", hnap_action);
       
	   	// Shell command is built to run the previously written shell file
		// (File written by the PHP script)
        shell_command = "sh %s%s.sh > /dev/console &";
        }
        snprintf(cmd_to_execute, 0x100, shell_command, &PATH, hnap_action);

		// File is executed containing the command injection
        system(cmd_to_execute);
    }
...
```

Once the analysis for this function was completed, I decided to take a look at the PHP file `SetAccessPointMode.php` &mdash; that in the end was the one containing the flaw &mdash; and tried to put all the pieces together:

```PHP
...
$IsAccessPoint	= query("/runtime/hnap/SetAccessPointMode/IsAccessPoint");
...
fwrite("w",$ShellPath, "#!/bin/sh\n");
fwrite("a",$ShellPath, "echo [$0] $1 ... > /dev/console\n");
fwrite("a",$ShellPath, "echo IsAccessPoint = ".$IsAccessPoint." > /dev/console\n");
fwrite("a",$ShellPath, "echo Result = ".$Result."\n");
...
```
As we can see, we have our `$ShellPath` variable which is filled by the function `hnap_main` and the `$IsAccessPoint` variable which is user-controlled and passed in the XML request sent. With this we can corroborate how an OS command injection in the variable written by the PHP file is executed. [Here you can find a full poc developed by pr0v3rbs to exploit this issue.](https://github.com/pr0v3rbs/CVE/blob/master/CVE-2018-19986%20-%2019990/poc.py)

We'll discuss a little bit more about the affected and fixed versions later. As you can see in the table below, it looks like there was some kind of regression with the patch, which reintroduced this vulnerability in versions that should have already been patched.

## Firmware versions analyzed

| Firmware                            | Version         | MD5 hash                         | Release date | Vulnerable |
|-------------------------------------|-----------------|----------------------------------|--------------|:----------:|
| DIR822C1_FW315WWb02.bin             | 3.15B02 WW      | 7121771c3e1706ba76fbf244023efad3 | 06/11/2019   | NO         |
| DIR822C1_FW313WWb01.bin             | FW v3.13        | aa16c7016f67be384e0784e439ce26d2 | 10/07/2019   | NO         |
| DIR822C1_FW303WWb04_i4sa_middle.bin | FW v3.12B04     | c3b9a3f115c02e739690616aba2f2d99 | 26/04/2019   | YES        |
| DIR822C1_FW312WWb04.bin             | FW v3.12B04     | eb11afbd136a5b29cea18141f727bfa8 | 26/04/2019   | YES (*)    |
| DIR822C1_FW311WWb01.bin             | FW v3.11        | 6d7c90eaaae835667faea65c862b3c82 | 01/01/2019   | YES        |
| DIR822C1_FW311bWWb01_icjg.bin       | 3.11B01_icjg_WW | 75e361e1465604aeda5d5dbcaecca977 | 21/12/2018   | NO         |
| DIR822C1_FW303WWb04_i4sa_middle.bin | FW v3.10B06     | c3b9a3f115c02e739690616aba2f2d99 | 17/08/2018   | YES        |
| DIR822C1_FW310WWb06.bin             | FW v3.10B06     | e33db75d0801fddb1c90308982e69fe5 | 17/08/2018   | YES (*)    |
| DIR-822_C1_FW302WWb05.bin           | FW v3.02        | 0dbf840c0ff5d3a5b593d33690e15d82 | 14/09/2017   | YES        |
| DIR822C1_FW301WWb02.bin             | FW v3.01B02     | 1bff7ec8b4da0643f65b4d44c630e92b | 27/04/2016   | YES        |

_(*) I did not check these firmware versions as their unencrypted counterparts were vulnerable._

As we can see in the table above, the vulnerability was fixed  in *some* firmware versions by removing the affected PHP file `SetAccessPointMode.php`. Once the file does not exist, checks performed in the function will fail and  nothing will be executed. I confirmed this analyzing the `hnap_function` in firmware versions `FW v3.131` and `3.15B02 WW`; the code for `hnap_main` did not change in relation to this issue, but the PHP file was not present anymore.

What's more interesting is that somehow this bug was reintroduced in firmware version `FW v3.11` up to `FW v3.12B04`, after being patched in version `3.11B01_icjg_WW`.

# Conclusions and next steps

As a first conclusion, I would say, never trust these devices as a real secure device &mdash;what happened with the updates is a clear example of why you shouldn't do so. Also, after the analysis performed I can conclude that the first PoC listed in this blog post will not work for this specific version, as we saw there are some conditions that have to be fulfilled to execute the vulnerable PHP file.

And the most important conclusion: be very careful when deciding how critical a vulnerability is based on its CVSS score. I decided to analyze this CVE as it was rated 9.8 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) and it's clear that, at least for this version, the attacker will need credentials to be able to exploit it.

As next steps I'll work on being able to emulate this binary to exploit this vulnerability without having access to the router itself, but that will be material for another post!

Thanks for reading.










## References
- [Ogur1 Writeup for CVE-2018-19986](https://translate.googleusercontent.com/translate_c?depth=1&pto=aue&rurl=translate.google.com&sl=zh-CN&sp=nmt4&tl=en&u=https://github.com/pr0v3rbs/CVE/blob/master/CVE-2018-19986%2520-%252019990/poc.py&usg=ALkJrhhpjXEw7R2jvMpl_xwizO2vL9Yu8A)
- [/dev/tty0 D-Link HNAP blogpost](http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/)
- [Pedro Ribeiro's HNAP advisory](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/dlink-hnap-login.txt)
- [CVE-2018-19987 PoC #0](https://github.com/ceballosm/scratchpad/blob/28da8dbceffe26cccbdb5124227de9201948596d/CVE-2018-19987.rb) by Mario Ceballos
- [CVE-2018-19987 PoC #1](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2018-19986%20-%2019990#cve-2018-19987---hnap1setaccesspointmode) by Mingeun Kim
- [CVE-2018-19987 details Link](https://www.cvedetails.com/cve/CVE-2018-19987/)
- [Decrypting D-Link firmware](https://payatu.com/blog/munawwar/solving-the-problem-of-encrypted-firmware)
- [Binwalk](https://github.com/ReFirmLabs/binwalk)
- [pro0v3rbs Poc](https://github.com/pr0v3rbs/CVE/blob/master/CVE-2018-19986%20-%2019990/poc.py)
