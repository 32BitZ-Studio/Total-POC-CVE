
<h1 align = "center"> CVE-2007-5962 </h1>
<img src="img/banner.png" alt="banner">



## 1. Introduction

My tool is written in Python and exploits the CVE-2007-5962 vulnerability to perform a series of directory changes that crash the ftp daemon.
<pre>
        <b> *** DISCLAIMER!!! ***</b>
        Please note that the use of hacking tools without authorization is illegal and
        could result in legal problems. Therefore, it is important to use this tool
        only for testing purposes on systems where you have permission to act.
</pre>
## 2. conditions to exploit this vulnerability

- firewall disabled or compromised

- the attacker must know the username and password of an ftp account

- ftp passwords travel unencrypted and could be sniffed

## 3. help use
<img src="img/screenHelper.png" alt="screen helper">

## 4. source from which I took inspiration:

[vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption](https://www.exploit-db.com/exploits/5814)

