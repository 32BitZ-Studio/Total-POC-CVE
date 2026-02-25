# CVE-2022-0155 Proof-of-Concept (PoC)

This repository contains a demonstration of the [CVE-2022-0155](https://github.com/advisories/GHSA-74fj-2j2h-c42q) vulnerability.
The vulnerability was detected by [ranjit-git](https://huntr.com/users/ranjit-git) and is described in detail [here](https://huntr.com/bounties/fc524e4b-ebb6-427d-ab67-a64181020406).
The purpose of this PoC is to demonstrate that the vulnerability doesn't just apply to scenarios where [follow-redirects](https://www.npmjs.com/package/follow-redirects) is used as a direct dependency, but also when follow-redirects is used as an indirect/transitive dependency through [axios](https://www.npmjs.com/package/axios).

## Overview

The vulnerability affects the [follow-redirects](https://www.npmjs.com/package/follow-redirects) npm package prior to version 1.14.7. Follow-redirects extends the [built-in HTTP module](https://nodejs.org/api/http.html) with the ability to follow redirects.

To demonstrate the vulnerability, consider the following scenario:
1. follow-redirects is used to send a GET request to https://example.com.
2. https://example.com replies with a 3xx response code requesting a redirect to https://attackers-webserver.com.
3. follow-redirects then sends a GET request to https://attackers-webserver.com.

The vulnerability lies in step 3, where the vulnerable versions of follow-redirects include the same `Cookie` headers as the request in step 1.
This allows https://attackers-webserver.com to steal, for example, the user's session ID on https://example.com and gain access to the user's data. 

The attack depends on the attacker's ability to control the redirect to https://attackers-webserver.com.
In the PoC, an Express server is used to emulate the behavior of https://example.com.
The server has a single GET API endpoint `'/redirect'`, which redirects the client to the URL provided as a parameter.
This emulates a scenario where the attacker can control the URL the client is redirected to.

## PoC

```
npm install
node express-server.js
nc -l -v 8182 # or nc -lnvp 8182 on non-mac systems
node client.js 
```

You should see the terminal containing `nc` print this output:

```
GET / HTTP/1.1
Accept: application/json, text/plain, */*
Cookie: session=some-secret-value
User-Agent: axios/0.21.4
Host: localhost:8182
Connection: keep-alive
```

The vulnerability is illustrated by the presence of the `Cookie` header in the `nc` terminal, as the `nc` (Netcat) server is used to represent the attacker's web server.
