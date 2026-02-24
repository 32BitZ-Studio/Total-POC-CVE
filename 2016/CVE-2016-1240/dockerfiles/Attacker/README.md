In order to build and run images give this command inside a software folder

```sh
sh build.sh
```

### CVE-2008-2938 Tomcat path traversal
Exploitable with ./Metasploit, run `./exploit.py CVE-2008-2938 <host>:<port>`

### CVE-2014-1904 Spring path traversal
Exploitable with ./Metasploit, run `./exploit.py CVE-2014-3625 <host>:<port>`

### CVE-2014-2064 Jenkins information disclosure
Exploitable with ./Node, edit `config.json` while in Docker, run `./brute.js`

### CVE-2016-1240 Tomcat privilege escalation
Exploitable with ./Metasploit, run `./exploit.py CVE-2016-1240 <host>:<port>`