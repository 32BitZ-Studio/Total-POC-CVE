# Update - 5/10/2023
The CVE-2023-2123 ID was reserved and the PoC was published in the WPScan website: https://wpscan.com/vulnerability/44448888-cd5d-482e-859e-123e442ce5c1

# Details

Title: Unauthenticated Reflected Cross-Site Scripting in WP Inventory Manager Plugin for WordPress CMS</br>
Date: 2023-04-15</br>
Author: Danilo Albuquerque</br>
Vendor Homepage: https://wordpress.org</br>
Software Link: https://wordpress.org/download</br>
Version: WordPress 6.2</br>
Plugin's Name and Version: WP Inventory Manager 2.1.0.12</br>
Tested on: Brave (Version 1.50.119  Chromium: 112.0.5615.121 (Official Version)  64 bits)</br>

# PoC for Reflected XSS vulnerability in WP Inventory Manager 2.1.0.12

1. Go to the page that has the inventory items;
2. Access the item that you want;
3. Fill the form in the "Reserve This Item" section of the page and click on "Reserve" button;
4. Once you have been redirected to the "Your reservation has been submited" page, add the **ENCODED** payload ```%3Cscript%3Ealert%281%29%3C%2Fscript%3E``` in the ```message``` parameter in the URL;
5. Press enter to do the request and voilá.

When you do all that and update the current page, it will bring you the alert pop-up with the message in it.

## Screenshots below

1. Go to the page that has the inventory items:</br>
![image](https://user-images.githubusercontent.com/85083396/232260162-6496fab3-5ae1-4672-a997-d1e770f94c79.png)

2. Access the item that you want:</br>
![image](https://user-images.githubusercontent.com/85083396/232260175-477a2754-f079-4b21-b93f-f961e1a5d539.png)

3. Fill the form in the "Reserve This Item" section of the page and click on "Reserve" button:</br>
![image](https://user-images.githubusercontent.com/85083396/232260256-12d288db-b913-4dda-a2cd-93536a5f1e11.png)

4. Once you have been redirected to the "Your reservation has been submited" page, add the **ENCODED** payload ```%3Cscript%3Ealert%281%29%3C%2Fscript%3E``` in the ```message``` parameter in the URL:</br>
![image](https://user-images.githubusercontent.com/85083396/232260438-1d74e0b2-0a72-4d36-adf3-29973fc5c0f7.png)

5.The alert pop-up:
![image](https://user-images.githubusercontent.com/85083396/232260446-f89c8172-cdd1-4c34-b942-e5e1d53df725.png)

# Bonus

You can also add a **DOUBLE ENCODED** malicious payload, and the attacker will be able to bypass some security controls such as not accept quotes.

The payload I used: ```%253Cscript%253Ealert%2528%2522pwned%2520by%2520daniloalbuqrque%2522%2529%253C%252Fscript%253E```

Screenshot below:</br>
![image](https://user-images.githubusercontent.com/85083396/232534487-87e9caca-e232-48c0-8dcc-4039892d4f6d.png)

