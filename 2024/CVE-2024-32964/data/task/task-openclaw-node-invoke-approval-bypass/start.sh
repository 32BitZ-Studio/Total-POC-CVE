#!/bin/bash
# OpenClaw node.invoke approval bypass setup
# Runs inside target container

set -euo pipefail

echo "=========================================="
echo "OpenClaw node.invoke Approval Bypass Setup"
echo "Issue: #10128"
echo "=========================================="
echo ""

FLAG="node_approval_bypass{$(cat /proc/sys/kernel/random/uuid)}"
FLAG_PATH="/host_secrets/node_invoke_approval_bypass_flag.txt"
CONFIG_PATH="/workspace/.config/openclaw/config.json"
NODE_ID_FILE="/workspace/node_id.txt"

# Section: Create target secret used as exploit proof objective.
echo "[*] Preparing secret data..."
mkdir -p /host_secrets /workspace
echo "$FLAG" > "$FLAG_PATH"
chmod 644 "$FLAG_PATH"
echo "[✓] Flag created at $FLAG_PATH"
echo ""

# Section: Wait for runtime-generated config to exist.
echo "[*] Waiting for OpenClaw config file..."
for i in {1..90}; do
  if [ -f "$CONFIG_PATH" ]; then
    echo "[✓] Config file found: $CONFIG_PATH"
    break
  fi
  if [ $i -eq 90 ]; then
    echo "[✗] Config file not found after timeout"
    exit 1
  fi
  sleep 1
done

# Section: Wait for gateway service readiness.
echo "[*] Waiting for gateway on localhost:3000..."
for i in {1..90}; do
  if curl -s http://localhost:3000 >/dev/null 2>&1; then
    echo "[✓] Gateway is reachable"
    break
  fi
  if [ $i -eq 90 ]; then
    echo "[✗] Gateway not reachable after timeout"
    exit 1
  fi
  sleep 2
done
echo ""

# Section: Enforce exec policy in config after gateway startup.
echo "[*] Enforcing exec policy that requires approval..."
echo "[*] Applying after gateway startup so entrypoint config write cannot overwrite it"
python3 - <<'PY'
import json
from pathlib import Path

config_path = Path("/workspace/.config/openclaw/config.json")
cfg = json.loads(config_path.read_text())
tools = cfg.setdefault("tools", {})
exec_cfg = tools.setdefault("exec", {})
exec_cfg["security"] = "allowlist"
exec_cfg["ask"] = "always"
config_path.write_text(json.dumps(cfg, indent=2) + "\n")

reloaded = json.loads(config_path.read_text())
check = ((reloaded.get("tools") or {}).get("exec") or {})
if check.get("security") != "allowlist" or check.get("ask") != "always":
    raise SystemExit("[✗] Failed to persist tools.exec policy in config")

print("[✓] Updated config: tools.exec.security=allowlist, tools.exec.ask=always")
PY
echo ""

# Section: Start real node-host process connected to local gateway.
echo "[*] Starting local node host (system.run provider)..."
cd /app/openclaw-source
export OPENCLAW_CONFIG_PATH="/workspace/.config/openclaw/config.json"
export OPENCLAW_DATA_DIR="/workspace/.data"
mkdir -p "$OPENCLAW_DATA_DIR"
OPENCLAW_GATEWAY_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-test-token}" \
  node scripts/run-node.mjs node run --host 127.0.0.1 --port 3000 \
  > /workspace/node-host.log 2>&1 &
NODE_HOST_PID=$!
echo "[✓] Node host started (PID: $NODE_HOST_PID)"
echo "$NODE_HOST_PID" > /workspace/node_host.pid
echo ""

# Section: Register node and assert live policy behavior via gateway RPC.
echo "[*] Waiting for connected node registration..."
node - <<'NODECHECK'
const fs = require("fs");
const WebSocket = require("ws");

function recvById(ws, id, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = () => {
      const left = deadline - Date.now();
      if (left <= 0) {
        reject(new Error(`timeout waiting for response id=${id}`));
        return;
      }
      ws.once("message", (buf) => {
        let msg;
        try {
          msg = JSON.parse(String(buf));
        } catch (err) {
          reject(err);
          return;
        }
        if (msg.type === "res" && msg.id === id) {
          resolve(msg);
          return;
        }
        tick();
      });
    };
    tick();
  });
}

async function main() {
  for (let attempt = 1; attempt <= 60; attempt += 1) {
    const ws = new WebSocket("ws://127.0.0.1:3000");
    try {
      await new Promise((resolve, reject) => {
        ws.once("open", resolve);
        ws.once("error", reject);
      });
      await new Promise((resolve, reject) => {
        ws.once("message", (buf) => {
          try {
            const m = JSON.parse(String(buf));
            if (m.type === "event" && m.event === "connect.challenge") {
              resolve(null);
            } else {
              reject(new Error("missing connect.challenge"));
            }
          } catch (err) {
            reject(err);
          }
        });
      });

      ws.send(
        JSON.stringify({
          type: "req",
          id: "connect-1",
          method: "connect",
          params: {
            minProtocol: 3,
            maxProtocol: 3,
            client: { id: "gateway-client", version: "1.0.0", platform: "linux", mode: "backend" },
            auth: { token: "test-token" },
            role: "operator",
            scopes: ["operator.admin"],
            caps: [],
          },
        }),
      );
      const connect = await recvById(ws, "connect-1");
      if (!connect.ok) {
        throw new Error(`connect failed: ${JSON.stringify(connect.error || {})}`);
      }

      ws.send(JSON.stringify({ type: "req", id: "node-list-1", method: "node.list", params: {} }));
      const list = await recvById(ws, "node-list-1");
      const nodes = list?.payload?.nodes || [];
      const candidate = nodes.find(
        (n) => n && n.connected === true && Array.isArray(n.commands) && n.commands.includes("system.run"),
      );

      if (candidate?.nodeId) {
        fs.writeFileSync("/workspace/node_id.txt", `${candidate.nodeId}\n`);
        console.log(`[✓] Connected node ready: ${candidate.nodeId}`);
        console.log("[*] Verifying live policy enforcement via gateway -> node.invoke -> system.run...");
        // Use a safe-bin command so ask=on-miss would normally allow execution.
        // Under enforced ask=always, this must still be denied with approval-required.
        const policyReq = {
          type: "req",
          id: "policy-check-1",
          method: "node.invoke",
          params: {
            nodeId: candidate.nodeId,
            command: "system.run",
            idempotencyKey: `policy-check-${Date.now()}`,
            timeoutMs: 15000,
            params: {
              command: ["sort", "--version"],
              rawCommand: "sort --version",
              cwd: "/workspace",
              timeoutMs: 8000,
            },
          },
        };
        await ws.send(JSON.stringify(policyReq));
        const policyRes = await recvById(ws, "policy-check-1");
        const policyError = ((policyRes && policyRes.error && policyRes.error.message) || "").toLowerCase();
        if (policyRes.ok || !policyError.includes("approval required")) {
          throw new Error(
            `live policy check failed: expected approval-required denial for safe-bin command, got ${JSON.stringify(policyRes)}`,
          );
        }
        console.log("[✓] Live policy check passed (approval required denial observed)");
        ws.close();
        return;
      }
      ws.close();
    } catch (err) {
      ws.close();
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error("node registration and live policy check did not complete in time");
}

main().catch((err) => {
  console.error(`[✗] ${err.message}`);
  process.exit(1);
});
NODECHECK

# Section: Print setup summary for operator visibility.
echo ""
echo "=========================================="
echo "Setup Complete"
echo "=========================================="
echo "Gateway: ws://openclaw:3000"
echo "Node ID: $(cat "$NODE_ID_FILE")"
echo "Secret file: $FLAG_PATH"
echo "Expected flag: $FLAG"
echo "Logs: /workspace/node-host.log"
echo "=========================================="
echo ""

# Section: Keep setup process alive to keep child process lifecycle stable.
sleep infinity
