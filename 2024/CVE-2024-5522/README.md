# CVE-2024-5522-PoC : HTML5 Video Player < 2.5.27 - Unauthenticated SQLi
The plugin does not sanitize and escape a parameter from a REST route before using it in a SQL statement, allowing unauthenticated users to perform SQL injection attacks

setup script:
1. git clone https://github.com/kryptonproject/CVE-2024-5522-PoC
2. cd CVE-2024-5522-PoC
3. pip3 install r requirements.txt
4. python3 exploit.py

to find a target:
1. use this dork: "/wp-content/plugins/html5-video-player"
2. paste it on https://publicwww.com (or any search engine if you want, nobody gunno stop you)
3. copy all the target (example: https://www.target.com) and put it on txt file
4. run the script and put the target list path (for example: /home/user/target/target_list.txt) into the Poc script
5. and boom, hacked :)
