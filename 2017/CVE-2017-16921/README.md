# OTRS-4.0.1-6.0.1 Remote Command Execution
This exploit is developed based on https://www.exploit-db.com/exploits/43853
It will perform the authentication against OTRS panel and provide a reverse shell.

Usage: python3 CVE-2017-16921.py <RHOST> <email> <password> <LHOST> <LPORT>

CVE-2017-16921:
In OTRS 6.0.x up to and including 6.0.1, OTRS 5.0.x up to and including 5.0.24, and OTRS 4.0.x up to and including 4.0.26, an attacker who is logged into OTRS as an agent can manipulate form parameters (related to PGP) and execute arbitrary shell commands with the permissions of the OTRS or web server user.

Credits to Hex_26 for the ChallengeToken retrieval function and Bæln0rn for the initial exploit.
