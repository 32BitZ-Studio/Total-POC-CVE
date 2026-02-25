# Proof of Concept for Login with Password Hash in STARFACE (CVE-2023-33243)

Details are described in our
[advisory](https://www.redteam-pentesting.de/advisories/rt-sa-2022-004).

In the corresponding [blog
post](https://blog.redteam-pentesting.de/2023/storing-passwords/) the
vulnerability CVE-2023-33243 is used as an example to describe how we generally
approach the analysis of authentication mechanisms and identify misconceptions
we encounter during our pentest engagements.

## Dependencies

Install Python libraries [requests](https://github.com/psf/requests) and
[click](https://github.com/pallets/click).

## Usage

```
python3 login.py --url [URL] --login [Login ID] --pwhash [SHA512 Password Hash]
```

