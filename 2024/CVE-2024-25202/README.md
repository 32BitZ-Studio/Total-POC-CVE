# CVE-2024-25202
A vulnerability was found in PHPgurukul visitor management system 1.0. it has been rated as problemic. Affected by the issue is some unknown functionality of the file search bar that called search-result.php and search-visitor.php . The vulnerability is Cross-Site-Scripting (XSS).
# Usage
One more Vulnerablity findings in PHPGURUKUL the name is Sql injection in Authentication Session.

Login

After login the account or bypass authentication through Sql injection then we need to go Search management in the top right side.

Payload

'"><svg/onload=confirm(/xsss/)>

![image](https://github.com/Agampreet-Singh/CVE-2024-25202/assets/73707055/71267e4b-1a5b-41f5-b847-5124b1f03732)



As You see i will search the code in Search Session.

![image](https://github.com/Agampreet-Singh/CVE-2024-25202/assets/73707055/6cf103ff-c91f-4a2d-b38b-1458525ea6de)

Xss Popup

According to the Scenario XSS vulnerability is valid in search-visitor or search-bar.php

# PoC (Proof Of Concept) Video Tutorial 
https://github.com/Agampreet-Singh/CVE-2024-25202/assets/73707055/7479c8cf-b6b7-4659-9be9-beb9bdb2153b

