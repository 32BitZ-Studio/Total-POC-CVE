# Descrip
PHPGurukul Online Shopping Portal 2.1 is vulnerable to Cross Site Scripting (XSS) in /admin/updateorder.php.

# Vulnerability Overview
1.Vulnerability Type: Stored Cross-Site Scripting (XSS)  
2.Affected Product: Online Shopping Portal Project - 2.1  
3.Affected Component: /shopping/admin/updateorder.php?oid=0  
4.Attack Type: Stored Cross-Site Scripting (XSS)

# Steps to Reproduce

1.Set Up the Application : Install and configure the vulnerable version (v2.1) on a local server. download from here  
``https://phpgurukul.com/shopping-portal-free-download/``  
![](./11.png)
2.Login to the System : Use the default credentials provided by phpgurukul.  
``admin/Test@123``  

3.Access the Vulnerable Functionality : /shopping/admin/updateorder.php?oid=0  
![](./22.png)  
4.paste the below code into content and choose the Status 'In Process' then click update  
``<script>alert(1)</script>``  
![](./33.png)  
![](./44.png)  
![](./55.png)  
5. Repeat into /shopping/admin/updateorder.php?oid=0  for a Stored Cross-Site Scripting (XSS)

# Link
``https://phpgurukul.com/shopping-portal-free-download/``


