# westone-CVE-2021-45232-scanner
Apache APISIX Dashboard earlier versions (2.10.1) has security vulnerability on unauthorized access.  
the Manager API uses two frameworks and introduces framework `droplet` on the basis of framework `gin`, all APIs and authentication middleware are developed based on framework `droplet`, but some API directly use the interface of framework `gin` thus bypassing the authentication.  
# Installation & Usage  
git clone https://github.com/Osyanina/westone-CVE-2021-45232-scanner.git  
cd westone-CVE-2021-45232-scanner  
cmd CVE-2021-45232.exe  
