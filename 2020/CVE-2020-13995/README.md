# Control Flow Hijack Exploit for CVE-2020-13995

Build it:

```
make
```

Run it:

```
make run
```

Mayhem it:

```
docker tag extract75-cve-2020-13955 <your name>/extract75-cve-2020-13955
docker push <your name>/extract75-cve-2020-13955
mayhem run --image <your name>/extract75-cve-2020-13955 \
    --project <your name>/extract75 .
```

(Default runtime is 600 seconds; override with --duration flag)

Need more information? Contact sales@forallsecure.com
