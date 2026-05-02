# Broken Access Control in CodeAstro Online Job Portal Allows Arbitrary Job Deletion

## Details
- **Vendor:** CodeAstro
- **Product:** Online Job Portal Project in PHP MySQL
- **Version:** 1.0
- **Vulnerability Type:** Broken Access Control (IDOR)
- **CWE:** CWE-639
- **Affected File:** /jobs/job-delete.php
- **Parameter:** id (GET)
- **Impact:** An authenticated employer can delete any other employer's 
job posting by manipulating the id parameter in the request.

## Description
The Online Job Portal Project in PHP MySQL developed by CodeAstro 
fails to verify whether the authenticated user owns the job posting 
before processing a delete request. By changing the `id` parameter 
in the GET request, an attacker can delete job postings belonging 
to other employers.

## Steps to Reproduce
1. Register two employer accounts (Employer A and Employer B)
2. Log in as Employer A and create a job posting — note the job ID
3. Log in as Employer B in a different browser
4. Intercept the delete request for Employer B's own job using Burp Suite
5. Change the `id` parameter to Employer A's job ID
6. Forward the request
7. Employer A's job posting is deleted successfully

## PoC Request
step 1:- 
GET /online-job-portal-php-mysql/jobs/job-delete.php?id=[victim_job_id] HTTP/1.1
Host: target
Cookie: [attacker_session_cookie]

from user A we will make a new job post and we will take note of the id here which is 41
<img width="1920" height="1080" alt="Screenshot 2026-04-06 032744" src="https://github.com/user-attachments/assets/1a7fdcb9-75f5-43d4-ac1b-7518da52e587" />

step 2 :- 
from the user B we will delete its job post but intercept it using burp 
<img width="1920" height="1080" alt="Screenshot 2026-04-06 032833" src="https://github.com/user-attachments/assets/e86fb130-7a35-49e6-acac-b21c5c4fa3af" />
<img width="1920" height="1080" alt="Screenshot 2026-04-06 032845" src="https://github.com/user-attachments/assets/00bc6673-0336-4b28-b3e9-eaa376fad35b" />
as we can see the user B job post id is 39

step 3 :-
we can change the job post id from 39 to 41 and delete user A job post with user B account
<img width="1920" height="1080" alt="Screenshot 2026-04-06 032858" src="https://github.com/user-attachments/assets/40efcccc-ca48-434b-add6-db86821e52f3" />
in this picture we can see that the job post id has been changed from 39 to 41 

and then we can see that it has been successfully deleted 
<img width="1920" height="1080" alt="Screenshot 2026-04-06 032918" src="https://github.com/user-attachments/assets/f277d875-72ce-4943-b9dd-c188d778e2b6" />

step 4 :- 
if we go to the user A account and look for the postedJobs endpoint we can see that the job post has been deleted 
<img width="1920" height="1080" alt="Screenshot 2026-04-06 032940" src="https://github.com/user-attachments/assets/0c7f6ecb-4e66-44be-9989-c223668ca308" />


## Response
HTTP/1.1 302 Found
Location: /online-job-portal-php-mysql/users/postedjobs.php?msg=deleted

## Impact
Any authenticated employer can permanently delete job postings 
belonging to other employers on the platform, causing data loss 
and disruption of service.

## References
https://codeastro.com/online-job-portal-project-in-php-mysql-with-source-code/
