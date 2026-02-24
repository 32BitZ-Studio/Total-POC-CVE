# Llama Facts
This project was originally created for the Rochester Institute of Technology (RIT) Women in Cybersecurity (WIYCS) 2022 CTF competition. It is vulnerable to Server-Side Template Injection (SSTI), defined in the disputed CVE CVE-2019-8341.

## Challenge Description
Description: A Computer Science 1 student created a website to showcase their newly-acquired python skills. Can you look into their search engine to ensure it is secure? 


## Usage
Requires having docker engine installed and running.  

`docker build -t wiycs_web . && docker run -p 5656:5656 -it wiycs_web`

Then navigate to `http://localhost:5656` and test your SSTI skills! Hopefully you'll learn a few llama facts along the way.


