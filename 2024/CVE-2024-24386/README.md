# VitalPBX - CVE-2024-24386

Vulnerability Title: Command Injection<br>
Author: Erick Duarte<br>
Version: < 3.2.5-2<br>

***

The vulnerability occurs when using the Task Manager module in conjunction with Cron Profile. To exploit this vulnerability, we need to place a script in a specific folder within the OS. The folder is "/var/lib/vitalpbx/scripts".

<img width="1310" alt="module-tas" src="https://github.com/erick-duarte/CVE-2024-24386/assets/59427098/5289217d-932a-4985-b919-f5850d4ef13e">

***

So, out of curiosity, I began analyzing what was being sent to the server using Burp. To do this, I created a Cron Profile to execute every minute.

![Untitled](https://github.com/erick-duarte/CVE-2024-24386/assets/59427098/78c71625-9fef-49b1-b00d-16f8b4fa8b58)

***

Next, I proceeded to create the Task Manager.

<img width="1432" alt="Untitled2" src="https://github.com/erick-duarte/CVE-2024-24386/assets/59427098/8e97b394-ce24-4dbd-8aa0-5c7ac9ff2e0f">

![Untitled3](https://github.com/erick-duarte/CVE-2024-24386/assets/59427098/9bc3d32a-9db7-44a2-b0ca-a121096cb296)

***

In the script field, I noticed that it passed the filename. So, I decided to insert a base64-encoded reverse shell payload (just to avoid errors with special characters) and sent it.

![Untitled4](https://github.com/erick-duarte/CVE-2024-24386/assets/59427098/70a95bcb-889e-410d-b892-1f438ad1035a)

***

Then, I sent the POST request just to apply the settings.

![Untitled5](https://github.com/erick-duarte/CVE-2024-24386/assets/59427098/4f9f725c-fa3f-45ce-a4b7-bff08a71db2d)

***

And there it is, we got the shell.

![Untitled6](https://github.com/erick-duarte/CVE-2024-24386/assets/59427098/cfd5086f-daff-4dcf-affc-f7c2d348c3fd)

***

I understand that a relatively high level of privilege is necessary, and it also depends on having a script in the specific directory. In VitalPBX, it is possible to create multiple users and grant various types of permissions. What would happen if these permissions were misconfigured? Additionally, there is the option to create a Tenant. If one of these Tenants manages to exploit this vulnerability, they could potentially gain full access to the server, including other Tenants.

I hope that my findings contribute to the security community, and I trust that VitalPBX will make the necessary corrections.

