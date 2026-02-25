**Project Name & Repo URL:**
[Maid Hiring Management System using PHP and MySQL](https://phpgurukul.com/maid-hiring-management-system-using-php-and-mysql/)

**Vulnerability Type:**
Privilege Escalation via Blind XSS

**Affected Version(s):**v1.0

**💣Vulnerability Description:**
A Blind Cross-Site Scripting (XSS) vulnerability was discovered in the Maid Hiring Management System, which allows a regular user (such as a maid or employer) to escalate their privileges and potentially take control of an administrative account.
![image](https://github.com/user-attachments/assets/2b70d227-58c3-4de0-809e-ba70a542c618)

**👩‍💻Impact:**
Full admin account takeover, access to sensitive data, and system manipulation.

**🛜Proof-of-Concept (PoC)**
1) There was mhms/maid-hiring.php, where a user can apply for job post.
2) Fill out the form with a Blind XSS payload in **Name** Field and Submit the Form.
![1](https://github.com/user-attachments/assets/49870910-a6d7-46f3-98a0-f917dce6f92d)
3) When the admin view the application, the Blind XSS payload will get trigged.
![3](https://github.com/user-attachments/assets/91eaaa65-c58f-459f-84e4-be4d03f15d59)
![4](https://github.com/user-attachments/assets/a10a35be-2508-4342-af0a-502bf809faef)
4) View the Response of the Blind XSS Payload, which contains admin **Session-Cookie**.
![5](https://github.com/user-attachments/assets/e623db19-9dfe-42ba-8d28-6eea1977c5b1)
![6](https://github.com/user-attachments/assets/2d5c9d21-100f-4c39-af51-d8c3fb8a4f17)
5) Use the admin cookie to escalate the privilege.
![8](https://github.com/user-attachments/assets/0e9b74dd-fa13-4d6a-a008-19289ad5897c)
![9](https://github.com/user-attachments/assets/7d03a0da-7029-4f3e-add2-420ef61fe2a7)

**Recommendation:**
Sanitize input, apply output encoding, and implement CSP.
