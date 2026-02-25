# CSV-Injection-PoC
CSV Injection in Addactis IBNRS 3.10.3.107<br>
AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:L<br>
CVSS: 7.1, Impact Score: 5.3, Exploitation Score: 1.3<br>
Affected Components: Project Description, Identifiers, Custom Triangle Name (inside Input Triangles) and Yield Curve Name parameters<br>


<img width="960" alt="newpoc1" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/3a239d2b-89fa-4045-9ee4-ec8d1917865b"><br>
<strong>Screenshot 1:</strong> Injecting an Excel Formula as Project Description in order to Open Notepad

<img width="959" alt="newpoc2" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/979f8acd-85cc-41d8-8d55-27c272225a9d"><br>
<strong>Screenshot 2:</strong> Saving the Malicious IBNRS Project that Contains the Formula as csv_injection_poc.ibnrs


<img width="960" alt="newpoc3" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/e96a4e78-990f-468f-8d33-91427d74860b"><br>
<strong>Screenshot 3:</strong> Displaying the Saved File Location From Addactis IBNRS

<img width="960" alt="newpoc4" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/383cb499-586a-4fcc-b7d2-e20ca9463fa0"><br>
<strong>Screenshot 4:</strong> Opening an Empty Excel Document


<img width="960" alt="newpoc5" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/4eace74d-5ef2-444e-a09b-dd1cc73cac13"><br>
<strong>Screenshot 5:</strong> Exporting the Malicious .ibnrs File via Add-ins Tab in Excel


<img width="960" alt="newpoc6" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/d7cf3ebb-b647-4fba-8d4d-9bffffc3788f"><br>
<strong>Screenshot 6:</strong> Waiting for File to be Loaded

<img width="960" alt="newpoc7" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/57af0f53-d5df-4dba-868a-a2391a5796ce"><br>
<strong>Screenshot 7:</strong> OS Command Execution Request After Exporting IBNRS Project with Malicious Formula


<img width="960" alt="newpoc8" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/39eb77d4-aea7-49da-9b9b-ce45438b85cd"><br>
<strong>Screenshot 8:</strong> Successfully Opening Notepad and Observing that the Project Description is Interpreted as Excel Formula

<img width="960" alt="newpoc9" src="https://github.com/c0rvane/CSV-Injection-PoC/assets/154702425/991e8067-0353-4316-99ae-90bcfd369965"><br>
<strong>Screenshot 9:</strong> Displaying the Injected Excel Formula in Project Description Cell
