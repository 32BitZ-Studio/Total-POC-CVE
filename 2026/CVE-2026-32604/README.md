# Spinnaker Vulnerability POCs

Proof-of-concept demonstrations for CVE-2026-32604 and CVE-2026-32613, two 10.0 severity vulnerabilities in Spinnaker that allow for code execution and production cloud credential theft.

- [Video walkthrough of how to use these POCS](https://youtu.be/ma-00ggxSp4)
- [Technical blog with more details](https://zeropath.com/blog/spinnaker-rce-production-compromise)


## Vulnerabilities

### Git Clone Shell Injection (CVE-2026-32604, CWE-78)

Clouddriver's artifact fetch endpoint passes the user-supplied branch name unsanitized into a `sh -c` command when using HTTP-based git authentication. Any authenticated user can inject shell commands via `PUT /artifacts/fetch`, achieving arbitrary code execution on the Clouddriver host -- the service that holds all cloud provider credentials. No special roles or permissions are required beyond being an authenticated user.

### SpEL RCE via expectedArtifacts (CVE-2026-32613, CWE-917)

Echo evaluates expected artifact declarations using Spring Expression Language (SpEL) with an unrestricted `StandardEvaluationContext` when a pipeline trigger fires. An attacker with write access to any application can save a pipeline containing a malicious SpEL expression, then fire a webhook trigger to get arbitrary code execution on the Echo service. Every other SpEL evaluation point in Spinnaker uses a hardened context; this is the only one that does not.

## Repository Contents

- **`setup/`** — Automated environment setup. Clones the Spinnaker source tree, builds all services from source, and stands up a fully configured cluster (Gate, Orca, Clouddriver, Front50, Fiat, Echo) with supporting infrastructure (Redis, MySQL, Elasticsearch, Minio, OpenLDAP). Includes seed data with test applications, users, and pipelines.

- **`pocs/`** — Exploit scripts. Each POC connects to Gate, sets up the attack, and drops the user into an interactive reverse shell on the target service container.
  - `clouddriver_rce_via_git_clone.py` — Git clone shell injection
  - `echo_rce_via_spel.py` — SpEL RCE via expectedArtifacts

## Instructions

Prerequisites: Docker, Git, Python 3.10+, and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
cd setup
./setup.sh
```

The first run clones the Spinnaker source and builds all services (~20-30 min depending on machine). Subsequent runs reuse the cached build and start in a few minutes.

When setup completes, it prints the full environment details (service URLs, credentials, and example POC commands). Follow those instructions to run the POCs.

To tear down:

```bash
cd setup
./teardown.sh
```
