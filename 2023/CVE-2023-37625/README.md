# Netbox-CVE-2023-37625
## Description
A stored cross-site scripting (XSS) vulnerability in Netbox < 3.4.7 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Custom Link templates.

## Technical Details
A stored Cross-Site Scripting vulnerability was discovered in the custom link function of the web application. This vulnerability is a result of insufficient sanitisation of the Link URL field.

To reproduce this vulnerability, the following steps may be performed:

1. Navigate to Custom Links under the Other tab.
2. Create a custom link with the following Link URL value, and assign the link to a model. In this example 'manufacturer' has been selected.:

```
{{'test1"</a><script>alert(1)</script>'}}
```

<img width="1094" alt="XSScustomlink" src="https://github.com/benjaminpsinclair/Netbox-CVE-2023-37625/assets/93361940/77ceb82d-8d12-490d-97bc-5d2db45a3260">

3. Add a new model, in this example add a 'manufacturer' model.

<img width="1238" alt="addmanufacturer" src="https://github.com/benjaminpsinclair/Netbox-CVE-2023-37625/assets/93361940/4e12634f-6bc6-4317-a827-14b41da5075f">

4. Open the newly created model as any authenticated user, and observer that the alert box has executed.
   
<img width="1104" alt="payload" src="https://github.com/benjaminpsinclair/Netbox-CVE-2023-37625/assets/93361940/f5ada457-d359-4f9b-b070-9d64dee9550a">
