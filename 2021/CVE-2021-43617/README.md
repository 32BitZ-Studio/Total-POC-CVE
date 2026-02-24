# CVE-2021-43617
This is a reproduction of PHP Laravel 8.70.1 - Cross Site Scripting (XSS) to Cross Site Request Forgery (CSRF) vulnerability

# Description 
The vulnerability exploits the fact that we can bypass laravel image file upload functionality to upload arbitary files on the web server which let us run arbitary javascript and bypass the csrf token

# Steps to reproduce:
* Creation of a Laravel 8.7.* application displaying an upload image file form
* Creation of a html file [csrfbypass.html](https://github.com/Sybelle03/CVE-2021-43617/blob/main/xss-csrf-vul/resources/views/csrfbypass.html) which contains the exploit to bypass form csrf token. 
* Use of HxD tool to add FF D8 FF E0 at the very begining of the file (giving the [csrfbypass_util.html](https://github.com/Sybelle03/CVE-2021-43617/blob/main/xss-csrf-vul/resources/views/csrfbypass_util.html) file)
* Upload this one on the application and try to display it. The csrf token is displayed in the alert(javascript)
