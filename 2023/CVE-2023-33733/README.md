# CVE-2023-33733 on Reportlab v3.6.12
This lab was set up to test CVE-2023-33733.

## Analyzing process
You can see our analyzing process about this CVE in PDF file on main repo.

## Setup and Run

### Server
#### Setup
```bash
pip3 install -r requirements.txt
```
#### Run
```bash
python3 app.py
```
### Attacker

#### Connect to server

Connect to server IP address
```http://{Server_IP}:4444```<br>
After running, you will see an interface like this, you can upload malicious HTML file to see the RCE.
![Screenshot 2024-04-22 194130](https://github.com/buiduchoang24/CVE-2023-33733/assets/166605385/e504481a-9252-4b8e-b84d-ccab69217c4c)

#### Listening and uploading file
```bash
nc -lvnp 4444
```
Then, upload your evil.html and get the reverse shell
![image](https://github.com/buiduchoang24/CVE-2023-33733/assets/166605385/ffc6a9ea-35b8-4d6e-a6e7-35ede299328e)




