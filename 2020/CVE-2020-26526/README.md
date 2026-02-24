# SmartAsset-UE-CVE-2020-26526
It is possible to enumerate valid usernames on the login page.

CVE-2020-26526

An issue was discovered in Damstra Smart Asset 2020.7.
It is possible to enumerate valid usernames on the login page. The
application sends a different server response when the username is
invalid than when the username is valid ("Unable to find an APIDomain" versus "Wrong email or password").

When the username is invalid, the server responds with:
"Unable to find an APIDomain for the email test@testtest.com, please contact your system administrator"

If the username is valid, the server responds with:
 "Login Failed! Wrong email or password." 
 
 ------------------------------------------

[Discoverer]
Lukasz Studniarz
