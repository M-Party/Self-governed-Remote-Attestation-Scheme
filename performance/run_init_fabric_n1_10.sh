#!/bin/bash
# SRAS init performance over Fabric: N=START..END (default 1..10).
# Between each N, restarts Fabric volumes so leftover workers/quotes cannot poison the next run.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PERF_DIR="${1:-performance_data/init_fabric_hpi_n1_10}"
START="${2:-1}"
END="${3:-10}"
RESET_LEDGER="${RESET_LEDGER:-1}"
FABRIC_NET="$ROOT/fabric_service/fabric_network"
case "$PERF_DIR" in
  /*) ;;
  *) PERF_DIR="$ROOT/$PERF_DIR" ;;
esac
mkdir -p "$PERF_DIR" "$PERF_DIR/logs"
LOG="$PERF_DIR/batch_run.log"
exec > >(tee -a "$LOG") 2>&1

echo "==== fabric init batch START $(date -Is) root=$ROOT perf=$PERF_DIR N=$START..$END reset_ledger=$RESET_LEDGER ===="

reset_fabric_ledger() {
  echo "---- reset Fabric ledger $(date -Is) ----"
  rm -rf /tmp/hfc-kvs /tmp/hfc-cvs /tmp/hfc-kvs-* /tmp/hfc-cvs-*
  local deploy_log="$PERF_DIR/logs/deploy_fabric_$(date +%s).log"
  (
    cd "$FABRIC_NET" || exit 1
    sudo HLF_VERSION=1.4.12 docker compose -f fixtures/docker-compose-2orgs-4peers-tls.yaml down -v --remove-orphans >/dev/null
    sudo HLF_VERSION=1.4.12 docker compose -f fixtures/docker-compose-2orgs-4peers-tls.yaml up -d >/dev/null
    sleep 5
    export PATH="$(pwd)/bin:$PATH"
    # shellcheck disable=SC1091
    source venv/bin/activate
    python3 deploy_fabric.py
  ) >"$deploy_log" 2>&1
}

stop_ports() {
  local n="$1"
  local i p
  python3 performance/start_multi_faric.py --num-parties "$n" --stop >/dev/null 2>&1 || true
  for i in $(seq 1 "$n"); do
    p=$((4432 + i))
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
    p=$((4454 + i))
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
    p=$((50050 + i))
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
  done
  for p in $(seq 4433 4442) $(seq 4455 4464) $(seq 50051 50060); do
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
  done
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    local busy=0
    for p in $(seq 4433 $((4432 + n))) $(seq 4455 $((4454 + n))) $(seq 50051 $((50050 + n))); do
      if fuser "${p}/tcp" >/dev/null 2>&1; then
        busy=1
        break
      fi
    done
    if (( busy == 0 )); then
      break
    fi
    sleep 0.5
  done
  sleep 1
}

for N in $(seq "$START" "$END"); do
  echo ""
  echo "======== N=$N $(date -Is) ========"
  stop_ports "$N"
  if [[ "$RESET_LEDGER" == "1" ]]; then
    if ! reset_fabric_ledger; then
      echo "ERROR: ledger reset failed for N=$N" | tee -a "$PERF_DIR/failures.log"
      continue
    fi
  fi
  rm -rf RPE_party* RPO_party* fabric_client_party*
  python3 performance/setup_multi_party.py \
    --num-parties "$N" \
    --transport fabric
  nohup python3 performance/start_multi_faric.py \
    --num-parties "$N" \
    > "$PERF_DIR/logs/fabric_clients_n${N}.log" 2>&1 &
  local_deadline=$((SECONDS + 120))
  ready=0
  while (( SECONDS < local_deadline )); do
    ready=0
    for i in $(seq 1 "$N"); do
      p=$((50050 + i))
      if fuser "${p}/tcp" >/dev/null 2>&1; then
        ready=$((ready + 1))
      fi
    done
    if (( ready == N )); then
      break
    fi
    sleep 1
  done
  echo "Fabric clients ready: ${ready}/$N"
  if (( ready != N )); then
    echo "ERROR: fabric clients not ready for N=$N" | tee -a "$PERF_DIR/failures.log"
    stop_ports "$N"
    continue
  fi
  sleep 2
  if ! python3 performance/performance_test.py \
      --test phase1 \
      --single "$N" \
      --perf-dir "$PERF_DIR"; then
    echo "ERROR: performance_test failed for N=$N" | tee -a "$PERF_DIR/failures.log"
    stop_ports "$N"
    continue
  fi
  python3 - << PY
import json
from pathlib import Path
p = Path("$PERF_DIR") / "test_result_${N}rpes.json"
if not p.exists():
    print("WARN: missing result file", p)
    raise SystemExit(0)
d = json.loads(p.read_text())
stats = d.get("statistics", {})
print("N=$N t_exchange", stats.get("t_exchange"))
print("N=$N t_join", stats.get("t_join"))
print("N=$N phase2", stats.get("phase2"))
bars = [x.get("durations", {}).get("pre_phase2_barrier") for x in d.get("individual_perf", {}).values()]
bars = [b for b in bars if b is not None]
hpis = [x.get("durations", {}).get("t_hpi_agree") for x in d.get("individual_perf", {}).values()]
hpis = [b for b in hpis if b is not None]
if bars:
    print("N=$N barrier_avg", sum(bars)/len(bars))
if hpis:
    print("N=$N t_hpi_avg", sum(hpis)/len(hpis))
if not stats.get("t_exchange"):
    print("WARN: missing t_exchange stats for N=$N")
PY
  stop_ports "$N"
  sleep 2
done

echo "==== generate summary ===="
python3 performance/performance_test.py \
  --perf-dir "$PERF_DIR" \
  --report-from $(seq "$START" "$END")

echo "==== fabric init batch DONE $(date -Is) ===="
ls -la "$PERF_DIR"/test_result_*rpes.json "$PERF_DIR"/summary_report* 2>/dev/null || true
