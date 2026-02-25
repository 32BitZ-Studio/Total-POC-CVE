# CVE-2022-25257

SAS Logon 9.4 allows warning-message injection.

Discovered: February 15, 2022

Affected Versions:

9.4

POC Exploit:

SASLogon/csrf has one parameter called "target"

This parameter affects the warning message for the URL the user was about to open (but, because of the unknown origin, the system blocks it).
By changing the parameter, one can write a long fake statement that can affect an unaware user.

Example for a payload: https://example:8343/SASLogon/csrf?target=Hello%20Dear%20customers%20during%20the%20corona%20pandemic%20our%20new%20website%20is%20at%20http://evilRobertsWeb.com%20please%20visit%20this%20link%20to%20reset%20the%20password

Pictures:

<img width="530" alt="image" src="https://user-images.githubusercontent.com/68341018/154493478-70473985-9d03-4153-b3e8-b14fd2748a2f.png">


