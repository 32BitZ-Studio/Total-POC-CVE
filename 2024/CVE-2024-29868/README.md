# CVE-2024-29868: Use of Cryptographically Weak PRNG in Recovery Token Generation

![cover](cover.png)

This repository contains the proof of concept related to **CVE-2024-29868** that affects Apache StreamPipes from v0.69.0 through 0.93.0.
**Description**: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) vulnerability in Apache StreamPipes user self-registration and password recovery mechanism. This allows an attacker to guess the recovery token in a reasonable time and thereby to take over the attacked user's account.
This POC demonstrate how it's possible to take over the admin account of the affected application.

### Repository Structure:

-   The `/lab-setup` directory contains the necessary files to spin up a local testing environment where it's possible to reproduce the vulnerabilility:
    -   `docker-compose.yml` file with all the necessary services.
    -   `.env` environment variables file.
-   The `/detection` directory contains 2 Project Discovery's Nuclei templates:
    -   `apache-streampipes-detect.yaml`: template to detect Apache StreamPipes installations.
    -   `CVE-2024-29868.yaml`: template to identify CVE-2024-29868 vulnerability.
-   The `/exploitation` directory contains the code to compile the cracker and instructions on how to use it.

Clone this repository and follow the `README.md` instructions in the respective directories.

### Resources & References:

-   [https://lists.apache.org/thread/zqn5z48gz7bp0q8ctk96ht8bc7vd3njv](https://lists.apache.org/thread/zqn5z48gz7bp0q8ctk96ht8bc7vd3njv)

-   [https://www.cve.org/CVERecord?id=CVE-2024-29868](https://www.cve.org/CVERecord?id=CVE-2024-29868)
  
-   [https://labs.yarix.com/2024/06/cve-2024-29868/](https://labs.yarix.com/2024/06/cve-2024-29868/)

-   [https://github.com/alex91ar/randomstringutils/tree/master](https://github.com/alex91ar/randomstringutils/tree/master)

-   [https://github.com/jhipster/generator-jhipster/issues/10401](https://github.com/jhipster/generator-jhipster/issues/10401)

-   [https://cwe.mitre.org/data/definitions/338.html](https://cwe.mitre.org/data/definitions/338.html)

-   [https://commons.apache.org/proper/commons-lang/apidocs/org/apache/commons/lang3/RandomStringUtils.html](https://commons.apache.org/proper/commons-lang/apidocs/org/apache/commons/lang3/RandomStringUtils.html)

-   [https://docs.oracle.com/javase/8/docs/api/java/util/Random.html](https://docs.oracle.com/javase/8/docs/api/java/util/Random.html)
