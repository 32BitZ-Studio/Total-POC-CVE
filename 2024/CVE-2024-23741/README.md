# CVE-2024-23741
An issue in Hyper through 3.4.1 on macOS allows a remote attacker to execute arbitrary code via the RunAsNode and enableNodeClilnspectArguments settings.

There is a tool designed to automate the process of searching for vulnerabilities in electron: https://github.com/r3ggi/electroniz3r
<img width="543" alt="image" src="https://github.com/V3x0r/CVE-2024-23741/assets/83291215/cd6660d9-0321-42ca-8edf-d525026e2d0e">

 
 
 With this tool, we can check if the App is Vulnerable:
 
 <img width="839" alt="image" src="https://github.com/V3x0r/CVE-2024-23741/assets/83291215/21fdd284-0e4f-4bef-9a26-e2334c443c08">

 
 
 After validation, we can inject our code, and get a shell
 
 
 <img width="845" alt="image" src="https://github.com/V3x0r/CVE-2024-23741/assets/83291215/533c0e51-13a6-49ae-9ef1-7acf8b7b8311">



 Enjoy Your Shell :)
