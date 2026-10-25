#!/usr/bin/env bash
# E2E for forge-iaas with the MOCK engine (no real infrastructure, ever).
# Flow: org -> workspace -> sensitive variable -> plan -> approve -> apply
# -> state v1 -> plan again -> approve -> apply -> state v2 -> MCP drift check
# -> drift clean. Also checks: sensitive value never leaks, plan-scoped
# key cannot approve.
# Usage: scripts/e2e-mock.sh   (builds ./fiaas-e2e binary, uses a temp dir)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'kill $SERVEPID 2>/dev/null || true; echo "--- workdir kept at $TMP"' EXIT
export PATH="$HOME/go/bin:$PATH" GOPATH="$HOME/gopath"
cd "$ROOT"
go build -o "$TMP/fiaas" ./cmd/fiaas
BIN="$TMP/fiaas"

mkdir -p "$TMP/cfg"
cat > "$TMP/cfg/main.tf" <<'EOF'
resource "aws_s3_bucket" "logs" {}
resource "aws_instance" "web" {}
EOF

export FIAAS_DB_PATH="$TMP/fiaas.db"
export FIAAS_ENGINE=mock
export FIAAS_MASTER_KEY="$(python3 -c "import base64; print(base64.b64encode(b'k'*32).decode())")"
export FIAAS_CONFIG_PATH="$TMP/config.json"

"$BIN" serve --addr :18099 --allow-anon > "$TMP/serve.log" 2>&1 &
SERVEPID=$!
for i in $(seq 1 50); do
  if curl -fsS http://127.0.0.1:18099/healthz >/dev/null 2>&1; then break; fi
  sleep 0.2
done
echo "== healthz:"; curl -s http://127.0.0.1:18099/healthz; echo

jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)"; }

echo "== create org (API)"
ORG_JSON="$(curl -fsS -X POST http://127.0.0.1:18099/api/v1/organizations -d '{"name":"Acme","slug":"acme"}')"
echo "$ORG_JSON"

S="--server http://127.0.0.1:18099"
echo "== create workspace (CLI remote)"
WS_JSON="$($BIN $S --json workspace create demo --org acme --config-path "$TMP/cfg" --execution-mode remote)"
echo "$WS_JSON"
WS_ID="$(echo "$WS_JSON" | jget "['id']")"
echo "workspace id: $WS_ID"

echo "== set sensitive variable (CLI remote, value must never leak)"
$BIN $S --json variable set demo SECRET_TOKEN=e2e-secret-value-123 --sensitive
echo "== variables list (must show *** not the secret)"
$BIN $S --json workspace get demo >/dev/null  # workspace exists check
curl -fsS http://127.0.0.1:18099/api/v1/workspaces/$WS_ID/variables
echo
if curl -fsS http://127.0.0.1:18099/api/v1/workspaces/$WS_ID/variables | grep -q "e2e-secret-value-123"; then
  echo "FAIL: secret leaked in variables list"; exit 1
fi

plan_apply_cycle() {
  echo "== plan (CLI remote, --wait)"
  PLAN_JSON="$($BIN $S --json run plan demo --wait)"
  echo "$PLAN_JSON"
  PLAN_ID="$(echo "$PLAN_JSON" | jget "['run_id']")"
  echo "plan run: $PLAN_ID"
  echo "== run detail after plan"
  curl -fsS http://127.0.0.1:18099/api/v1/runs/$PLAN_ID; echo
  echo "== approve (CLI remote)"
  APPROVE_JSON="$($BIN $S --json run approve $PLAN_ID)"
  echo "$APPROVE_JSON"
  APPLY_ID="$(echo "$APPROVE_JSON" | jget "['apply_run_id']")"
  echo "apply run: $APPLY_ID"
  echo "== wait for apply"
  for i in $(seq 1 50); do
    ST="$(curl -fsS http://127.0.0.1:18099/api/v1/runs/$APPLY_ID | jget "['status']")"
    echo "  apply status: $ST"
    [ "$ST" = "applied" ] && break
    [ "$ST" = "failed" ] && { echo "APPLY FAILED"; curl -fsS http://127.0.0.1:18099/api/v1/runs/$APPLY_ID; echo; exit 1; }
    sleep 0.2
  done
  echo "== state versions"
  curl -fsS http://127.0.0.1:18099/api/v1/workspaces/$WS_ID/state/versions; echo
  echo "== state (redacted)"
  curl -fsS http://127.0.0.1:18099/api/v1/workspaces/$WS_ID/state; echo
}

plan_apply_cycle
plan_apply_cycle

echo "== create admin + plan-only keys (CLI local mode, same DB)"
ADMIN_KEY="$($BIN key create --org acme --scopes admin --json | jget "['key']")"
PLAN_KEY="$($BIN key create --org acme --scopes plan,state:read-redacted --json | jget "['key']")"
echo "admin key prefix: ${ADMIN_KEY:0:11}..., plan key prefix: ${PLAN_KEY:0:11}..."

echo "== security: plan-scoped key must NOT approve (expect 403)"
PLAN2_JSON="$($BIN $S --json run plan demo --wait)"
PLAN2_ID="$(echo "$PLAN2_JSON" | jget "['run_id']")"
HTTP_CODE="$(curl -s -o /tmp/e2e-403-body.txt -w "%{http_code}" -X POST http://127.0.0.1:18099/api/v1/runs/$PLAN2_ID/approve -H "Authorization: Bearer $PLAN_KEY" -d '{}')"
echo "approve with plan key -> HTTP $HTTP_CODE: $(cat /tmp/e2e-403-body.txt)"
[ "$HTTP_CODE" = "403" ] || { echo "FAIL: expected 403"; exit 1; }
$BIN $S --json run discard $PLAN2_ID >/dev/null
echo "discarded the unapproved plan run"

echo "== MCP (stdio, admin key): workspace_list, state_read_redacted, drift_check"
python3 - "$BIN" "$ADMIN_KEY" "$TMP" <<'PYEOF'
import subprocess, sys, json, os
binpath, key, tmp = sys.argv[1], sys.argv[2], sys.argv[3]
env = dict(os.environ, FIAAS_AGENT_KEY=key, FIAAS_DB_PATH=os.path.join(tmp, "fiaas.db"), FIAAS_ENGINE="mock")
p = subprocess.Popen([binpath, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
def send(obj):
    p.stdin.write(json.dumps(obj) + "\n"); p.stdin.flush()
    line = p.stdout.readline()
    print("MCP>", line.strip()[:600])
    return json.loads(line) if line else {}
def notify(obj):
    # Notifications get NO response by protocol — never read after one.
    p.stdin.write(json.dumps(obj) + "\n"); p.stdin.flush()
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}})
notify({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"workspace_list","arguments":{"org":"acme"}}})
send({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"state_read_redacted","arguments":{"workspace":"demo"}}})
drift = send({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"drift_check","arguments":{"workspace":"demo"}}})
p.stdin.close(); p.wait(timeout=10)
print("MCP exit:", p.returncode)
PYEOF

echo "== wait for drift run, then drift report (must be clean)"
sleep 2
curl -fsS http://127.0.0.1:18099/api/v1/workspaces/$WS_ID/drift; echo
DRIFTED="$(curl -fsS http://127.0.0.1:18099/api/v1/workspaces/$WS_ID/drift | jget "['drifted']")"
echo "drifted=$DRIFTED"
[ "$DRIFTED" = "False" ] || { echo "FAIL: expected drift clean"; exit 1; }

echo "== audit log (must not contain the secret)"
curl -fsS "http://127.0.0.1:18099/api/v1/audit?workspace=$WS_ID" | tee "$TMP/audit.json" | head -c 2000; echo
if grep -q "e2e-secret-value-123" "$TMP/audit.json"; then echo "FAIL: secret in audit"; exit 1; fi

echo "E2E MOCK PASSED"
