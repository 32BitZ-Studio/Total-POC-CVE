# CVE-2022-39275

POC for [CVE-2022-39275](https://www.cve.org/CVERecord?id=CVE-2022-39275).
Resources for the advisory:

- [NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-39275)
- [CVE.org](https://www.cve.org/CVERecord?id=CVE-2022-39275)
- [Github Security Advisory](https://github.com/saleor/saleor/security/advisories/GHSA-xhq8-8c5v-w8ff)

This is a fork of commit hash: `47f9f5fb29be2b5892c79ace4f23022f397a0a5e` [link](https://github.com/saleor/saleor-platform/commit/47f9f5fb29be2b5892c79ace4f23022f397a0a5e), just re-pushed as there were git submodules that also had to be changed.

## POC-Setup

Follow the [setup guide](https://docs.saleor.io/setup/docker-compose). In case it's outdated, here are the steps:

```sh
cd saleor-platform
docker compose build

docker compose run --rm api python3 manage.py migrate
docker compose run --rm api python3 manage.py populatedb
docker compose run --rm api python3 manage.py createsuperuser

docker compose up
```

admin users are `admin@example.com` and `admin`. Regular users can be found in the saleor source code (I think most of them just have `password` as their password).

Getting the authentication token might be abit tricky (since it has an expiry mechanic using the refresh token. For more information, check [authentication-docs](https://docs.saleor.io/api-usage/authentication#email-and-password)). I won't help with this as doing all the steps above already assumes you have application security experience.

## POC

All you have to do is run [GraphQLer](https://github.com/omar2535/GraphQLer) to identify the POC. Once the POC is identified, craft your requests in your favorite request editor.
