# CVE-2021-46398 - Lalie ARNOUD, Gaspard ANDRIEU

In this repository, you will find a proof of concept of the exploitation of the CVE-2021-46398 flaw through a docker compose, as well as an analysis of the impacts of this flaw on information systems.

~~~
# Exploit Title: FileBrowser 2.17.2 - Cross Site Request Forgery (CSRF) to Remote Code Execution (RCE)
# Date: 05/02/2022
# Exploit Author: FEBIN MON SAJI
# Vendor Homepage: https://filebrowser.org/
# Software Link: https://github.com/filebrowser/filebrowser
# Version:
    FileBrowser <= 2.17.2
# Tested on: Ubuntu 20.04
# CVE : CVE-2021-46398
~~~

## What is FileBrowser ?
According to [FileBrowser's website](https://filebrowser.org/), FileBrowser is a popular create-your-own-cloud-kind of software that you can install on a server, direct it to a path and then access your files through a nice web interface developed in the Go language, with [many features](https://filebrowser.org/features). It's a bit like Google Drive except that everyone can own and host their own instance.

## Flaw description
FileBrowser's admins can create multiple users, even another admin privileged user, and give access to any directory he wants. The user creation is handled by an endpoint `/api/users`. The endpoint accepts input in [JSON](#glossary) format to create users, but fails to verify the `Content-Type` [HTTP](#glossary) header which value should be `application/json`, but accepts `text/plain`; and that’s where the vulnerability arises. Also, the `Origin` is not validated and there are no anti-[CSRF](#glossary) tokens implemented either. Hence an attacker can easily exploit this vulnerability to create a backdoor user with admin privileges and access to the home directory or whichever directory the attacker wants to access, just by sending a malicious webpage URL to the legitimate admin and access the whole server's filesystem (more explanation of this process in the demonstration section).

In addition, an admin can run commands on the system, so this vulnerability leads to an [RCE](#glossary).

Here is a sequence diagram that summarises the attack process (Alice being the hacker and Bob being the administrator and host of the FileBrowser instance):
```mermaid
sequenceDiagram
Alice (hacker) ->> Alice (hacker): *Maliciously creates the malicious HTML page*
Alice (hacker) ->> Bob (admin): Here is a cool page! You must check that bro!
Bob (admin) ->> Alice (hacker): Thanks dude, let's open that!
Bob (admin) ->> Bob (admin): *Opens the page thinking it's something cool*
Bob (admin) -->> FileBrowser: *Sends a request to create a user without knowing it*
FileBrowser -->> FileBrowser: *Creates a new admin privileged user as requested*
Alice (hacker) ->> FileBrowser: Eheheh Bob is so dumb! *Connect to FileBrowser with the backdoor user*
FileBrowser ->> Alice (hacker): *Accept Alice connection with the new user created*
Alice (hacker) ->> FileBrowser: *Request shell access to FileBrowser with the appropriate button then makes sytem calls on Bob's computer*
```

## Demonstration of the security flaw
The goal of this demonstration is to set up a mini-architecture composed of two/three machines:
- your personal computer as a FileBrowser's admin's computer on one side, and as the attacker on another side.
- a vulnerable Docker container simulating a remote FileBrowser server.

It is a really simplified architecture which aim is to highlights the technical aspect of the flaw.

### Launching the vulnerable machine's image
For this experiment, you will only need `docker`.

In this setup, the target machine is based on a FileBrowser v2.17.2 image (which is vulnerable to this flaw), in which the only FileBrowser's account is the administrator account that has `admin`/`admin` as login/password.

Launching the target machine:
```
mkdir srv && docker compose up
```
### Exploit

#### Create the malicious webpage
From the attacker's side, the malicious webpage will allow us to execute the FileBrowser API call and create our backdoor user from the administrator's computer.

An example of such a page is provided in this repository under the name `index.html`. It is a simple [HTML](#glossary) page with a hidden form that performs a [POST](#glossary) request to the `/api/users` FileBrowser's endpoint with the payload on the input's name. This payload creates an admin privileged user which login is "oui" and password's "oui", and is triggered when the button is clicked.

> We could obviously have created a prettier and more attractive page than this one and hide the sending of the [HTTP](#glossary) request in another element of the website, it's just so that you can see the technical aspect of the flaw's exploitation. Remember that the goal of this malicious webpage is to be opened by the FileBrowser's admin without them suspecting anything!

#### Execute the webpage's exploit by sending the HTML form
From the administrator's side, we are quietly doing admin stuff on FileBrowser. Go to `127.0.0.1:8080` and log in with admins credentials `admin`/`admin`.

Then, we received the malicious webpage by any means, like in a phishing email, and perform the action that triggers the exploit. Open the `index.html` webpage and click on the button; it launches the payload.

#### Access the FileBrowser backdoor user
Now, back to the attacker's side, we now have an admin privileged backdoor user on the FileBrowser server.

Open your favorite web browser in private browsing to ensure that you are not using any of the administrator's authentication means. Go to `localhost:8080` and log in with the backdoor user credentials `oui`/`oui`.

Congratulations! You now have access to the FileBrowser's server file system and thus to all server's users files!

And because FileBrowser is a great platform with lots of features, you can launch a terminal instance by pressing the "toggle shell" button... try typing `whoami`, and do whatever you want as root :)

> To allow the backdoor user to use shell commands, they have to be explicitly declared on the payload. See `index.html` to add yours!

## Fix
The flaw has been patched from the version v2.18.0. The informations about it are available on [their GitHub](https://github.com/filebrowser/filebrowser/issues/1621).  The patch was not very expensive to deploy as it only required 6 lines of code to be changed in a single program file. Since the vulnerability came from the parsing failure (cf. [flaw description](#flaw-description)), it was enough to ensure that any request was parsed into `application/json` format before being processed for anything else.

## Glossary
- [CSRF: Cross-Site Request Forgery](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
- [CVE: Common Vulnerabilities and Exposures](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)
- [POST: HTTP method](https://en.wikipedia.org/wiki/POST_(HTTP))
- [RCE: Remote Code Execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution)

## References
- [CVE-2021-46398](https://nvd.nist.gov/vuln/detail/CVE-2021-46398)
- [ExploitDB](https://www.exploit-db.com/exploits/50717)
- [Exploit example](https://packetstormsecurity.com/files/165885/FileBrowser-2.17.2-Code-Execution-Cross-Site-Request-Forgery.html)
- [Security patch from FileBrowser's GitHub](https://github.com/filebrowser/filebrowser/commit/74b7cd8e81840537a8206317344f118093153e8d)
- [Issue thread from FileBrowser's GitHub](https://github.com/filebrowser/filebrowser/issues/1621)

This work was done as part of the Information Systems Security course given in the last year of the Information Systems Engineering specialization at Grenoble INP - Ensimag, UGA.
