# seL4 HTTP Gateway Demo

HTTPS gateway running on the seL4 microkernel with EverParse-verified RBAC access control.

## Quick Start

```bash
docker build -t sel4-http-gateway .
docker run --rm -it -p 8443:8443 sel4-http-gateway
```

Wait ~10 seconds for `[ControlPlane] Ready:` to appear.

### Web Dashboard (Browser)

Open **https://localhost:8443** in your browser and accept the self-signed certificate warning.
The dashboard provides a web-based login interface to interact with the gateway.

### curl Examples (Terminal)

From a second terminal:

```bash
# 1. Unauthenticated request -> 403 Forbidden
curl -sk https://localhost:8443/api/status

# 2. Login as admin -> 200 OK
curl -sk -X POST -d '{"username":"admin","password":"admin456"}' https://localhost:8443/api/login

# 3. Authenticated request -> 200 OK
curl -sk https://localhost:8443/api/status

# 4. Logout -> 200 OK
curl -sk -X POST https://localhost:8443/api/logout

# 5. After logout -> 403 Forbidden
curl -sk https://localhost:8443/api/status
```

Exit QEMU: `Ctrl+A`, then `X`.

## What's Running

- **seL4 microkernel** on x86_64 (QEMU)
- **4 CAmkES components**: E1000Driver, TlsValidator, LwipProxy, ControlPlane
- **TLS 1.2** termination (self-signed cert, hence `-k` flag)
- **EverParse-verified** RBAC policy validators (Login, AccessRequest, PolicyBlob)
- **Session management** with role-based access (OPERATOR, ADMIN)

## Credentials

| Username | Password | Role |
|----------|----------|------|
| operator | oper123 | OPERATOR |
| admin | admin456 | ADMIN |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | None | Web dashboard |
| POST | `/api/login` | None | Login (JSON body) |
| POST | `/api/logout` | OPERATOR+ | End session |
| GET | `/api/status` | OPERATOR+ | Auth status |
| GET | `/api/policy` | ADMIN | Read policy |
| PUT | `/api/policy` | ADMIN | Upload policy |
