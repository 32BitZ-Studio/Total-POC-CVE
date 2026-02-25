# CVE-2024-22416

Reference report: [GHSA-pgpj-v85q-h5fm](https://github.com/pyload/pyload/security/advisories/GHSA-pgpj-v85q-h5fm)

This repository contains a docker compose configuration that setups both a pyLoad server
and an attacker server that just provides a `csrf.html`. To test yourself, just run
`docker composer up` (you need to have docker composer installed additionally to docker).

Then, start by going to `localhost:8000`, which is the pyLoad login page, and login with
user `pyload` and password `pyload`. Then, go to `localhost:8001/csrf.html`, this will
instantly submit a cross-site request to pyLoad API and add a user called "hacker".
You can check that it worked by going to Settings > Users and notice that "hacker" user
has been added!
