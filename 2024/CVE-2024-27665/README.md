# CVE-2024-27665

Unifiedtransform v2.X is vulnerable to Stored Cross-Site Scripting (XSS) via file upload feature in Syllabus module.  

Vendor: https://github.com/changeweb/Unifiedtransform

---

## PoC

Step 1: Log in to the Application and Navigate to Academic module.  
  
![image](https://github.com/Thirukrishnan/CVE-2024-27665/assets/63901950/61f8771f-588a-4d3c-ad10-1182d4ac6cd7)  

Step 2: Create Session,Semester,Class,Course from the Academic module with random data.  
  
Step 3: Navigate to Syllabus module, fill in the required details and upload [PDF file](https://github.com/Thirukrishnan/CVE-2024-27665/blob/main/xss.pdf) with XSS payload in the Syllabus File upload input.  
  
![image](https://github.com/Thirukrishnan/CVE-2024-27665/assets/63901950/bbb6375a-50f5-4adb-b2f2-512c1ef7e71f)  
  
Step 4: Navigate to Classes -> Syllabus and click on download.  
  
![image](https://github.com/Thirukrishnan/CVE-2024-27665/assets/63901950/ce50b1d1-c97b-42b2-8f79-1940416707c8)  
![image](https://github.com/Thirukrishnan/CVE-2024-27665/assets/63901950/298132a1-2478-4390-8382-946bbd9033f6)   
  
Step 5: Observe the XSS getting triggered!.  
  
![image](https://github.com/Thirukrishnan/CVE-2024-27665/assets/63901950/9cabf3aa-49ea-4ed4-a848-cb20bfce0bf3)  






