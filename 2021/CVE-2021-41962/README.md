# -CVE-2021-41962

>Description
> Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Vehicle Service Management System 1.0 via the Owner fullname parameter in a Send Service Request in vehicle_service.

> [Additional Information]
> NA


> [Vulnerability Type]
> Cross Site Scripting (XSS)

> [Vendor of Product]
> https://www.sourcecodester.com/

> [Affected Product Code Base]
> Vehicle Service Management System - 1.0
> [Affected Component]
> http://localhost/vehicle_service/

> [Attack Type]
> Remote

> [Impact Information Disclosure]
> true

> [Attack Vectors]
> Steps for reproduce:
> 1. Go to url http://localhost/vehicle_service/ 
> 2. Click on "Send Service Request"
> 3. Enter the payload <script>alert(1)</script> in the "Owner fullname" parameter
> 4. Click on "Submit request"
> 5. Login into admin panel http://localhost/vehicle_service/admin/
> 6. Click on "Service Requests" in the left bar
> 7. The pop up will be triggered.

> [Reference]
> https://owasp.org/www-community/attacks/xss/

> [Discoverer]
> M Lohith

Use CVE-2021-41962.

