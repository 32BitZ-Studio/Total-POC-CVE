# CVE-2026-33186

gRPC-Go RBAC Authorization Policy Bypass via Missing `:path` Slash (Auth Bypass)

## Description

The `authz` package in `google.golang.org/grpc` implements SDK-level RBAC
authorization using deny and allow rules matched against the `:path`
pseudo-header. The HTTP/2 server transport stores the raw `:path` value from
the client without validating that it starts with `/`. The routing layer
(`handleStream`) normalizes the path before dispatch, but the RBAC engine reads
the pre-normalization value from context via `grpc.Method(ctx)`.

Deny rules are written as `/Service/Method` (with leading slash). Sending
`:path = "Service/Method"` (without slash) causes the deny rule to miss on the
first-character comparison. The default allow fires, and the protected method
executes.

Any gRPC server using `authz.NewStatic()` or `authz.NewFileWatcher()` with
deny rules is vulnerable. A raw HTTP/2 client (Python `h2`, `curl --http2`, or
any custom frame writer) is sufficient to exploit this -- no credentials, no
prior state.

Live verification against grpc-go v1.71.0 returned gRPC status 0 (OK) on a
deny-listed `AdminMethod` when the leading slash was omitted, while the
identical call with the canonical slash returned status 7 (PermissionDenied).

Affected: `google.golang.org/grpc` < v1.79.3. Fixed in v1.79.3 (PR #8981).

## Usage

```bash
# Native (requires Go + Python 3 with h2):
pip install h2
./run.sh

# Docker (no local dependencies):
docker compose up --build --abort-on-container-exit

# Against an existing vulnerable gRPC server:
python3 poc.py --host <HOST> --port <PORT>
python3 poc.py --host <HOST> --port <PORT> --service MyService --method SecretMethod
```

## Requirements

- For native: Go (any recent version), Python 3.8+, `h2` (`pip install h2`)
- For Docker: Docker + Docker Compose
- Target: gRPC-Go server using `authz` package with deny rules

## Files

| File | Description |
|------|-------------|
| `poc.py` | Python PoC -- sends 3 raw HTTP/2 calls (baseline/attack/control) to prove the bypass |
| `server/main.go` | Vulnerable gRPC server with deny-list RBAC policy (grpc-go v1.71.0) |
| `server/go.mod` | Go module pinned to vulnerable grpc-go v1.71.0 |
| `run.sh` | Builds server, starts it, runs PoC, shows server log |
| `Dockerfile` | Multi-stage build (Go server + Python client) |
| `docker-compose.yml` | One-command Docker setup with health checks |
| `proto/service.proto` | Protobuf service definition |
| `proof_output.txt` | Full PoC output + server log from live verification |

## References

- https://github.com/grpc/grpc-go/security/advisories/GHSA-p77j-4mvh-x3m3
- https://github.com/grpc/grpc-go/pull/8981

## Legal Notice

This project is released under the GNU GPLv3.

It is provided for defensive security research, education, and authorized
testing. Do not use this code against systems or services without explicit
permission from the owner.

Unauthorized use may violate applicable law. The authors do not grant permission
to test third-party systems and are not responsible for misuse.

See the LICENSE file for warranty and liability terms.
