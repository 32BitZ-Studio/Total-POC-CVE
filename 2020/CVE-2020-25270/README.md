# CVE-2020-25270
PHPGurukul hostel-management-system 2.1 allows XSS via  Guardian Name, Guardian Relation,  Guardian Contact no,  Address, City

#Vendor - PHPGurukul

#Product -https://phpgurukul.com/hostel-management-system V2.1

#Vulnerability Type - Cross Site Scripting (XSS)

#Addition Information - XSS will be triggered in both side, user can escalate of admin privilege through stealing admin cookies.

#Affected Component - Books > New Book ,[ http:///lms/index.php?page=books] http:///lms/index.php?page=books

#Attack Type- Local

#Privilege Escalation - true

#Impact Code execution - true

> Attack Vector
> --------------
>
>  Install Hostel Management System V 2.1
>
>
> ***1) User Module***
> ------------------
>
> Login as user and go to "Book Hostel" (http:/localhost/hostel/book-hostel.php) and start booking.

>
> Add malicious script in these fields - "<script>alert('XSS');</script>"
> 
>  i.  Guardian Name

>  ii. Guardian Relation

>  iii.Guardian Contact no

>  iv. Address

>  vi. City

> 
> After that will get a prompt "Student Successfully register" and after pressing "See All", XSS will be triggered.




> 
> ***2) Admin Module***
> ------------------
>
> Login in as Admin and go to "Management Students", and "View Full details" of booked student's record, XSS will be triggered also.
