# Admin MD5 Password Hash Disclosure - ModernWMS v1.0 - CVE-2024-57698
An issue in modernwms v.1.0 allows an attacker view the MD5 hash of the administrator password and other attributes without authentication, even after initial configuration and password change. This happens due to excessive exposure of information and the lack of adequate access control on the /user/list?culture=en-us endpoint.

<p align="center">
  <img height=400 src="https://github.com/user-attachments/assets/2d9cf25a-32e4-470a-8aa4-ec8fc4ee1f97" />
</p>

---

#### Mode of Use
```
python CVE-2024-57698.py --host <IP> --port <port>
```
Link: https://youtu.be/5ZPFZDpDnYI
