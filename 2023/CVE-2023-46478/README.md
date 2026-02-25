# CVE-2023-46478

Minical 1.0.0 is vulnerable to IDOR .

Vendor:      <https://github.com/minical/minical>

Demo Application:  <https://demo.minical.io/>

---
## PoC

Step 1: I have created two user accounts user A (hacker) then user B (walker-448)

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/4d83d2bb-0765-4085-b5e1-67f483042549)

Step 2: Go to the User B account then Navigate to the Accounting module and then click on any ID. 

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/a42aff76-aa19-4c05-a022-e6f41893489c)

Step 3: Now, click on "Edit Profile". Enter the desired value in the Name field, then click "Update" and capture the request using Burp Suite.

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/92bc89a2-de85-4397-99f2-014f884fffd4)

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/bb57f94c-9c6d-4eba-8982-4633a17a2a9f)

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/c6a70a30-5eee-4351-a766-c4224d3e6b09)

Step 4: Now send the request to intruder.

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/2129a3bb-4d63-44a3-b80a-51b9e283e9c6)

 Step 5. Now, set the payload position in the "customer_id" parameter then enter the HTML payload in the "customer_data[customer_name]" parameter, and then click on 'Start Attack.
 
![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/5f81d4d0-5564-43f6-82b5-06e0a66229cc)

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/dc3daeb2-26b2-4271-83a6-7273a3571b77)

Step 6: Now, refresh the browser for user A. As can be observed, we successfully updated user A's details, as shown in the POC below.

![image](https://github.com/mr-xmen786/CVE-2023-46478/assets/79393031/5ba4ca89-cb00-4b5c-acf1-da900d4b24a9)


