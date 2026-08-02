#!/bin/bash
# SRAS init performance: N=1..10, P2P, no FT (consensus policy path).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PERF_DIR="${1:-performance_data/init_consensus_n1_10}"
START="${2:-1}"
END="${3:-10}"
mkdir -p "$PERF_DIR" "$PERF_DIR/logs"
LOG="$PERF_DIR/batch_run.log"
exec > >(tee -a "$LOG") 2>&1

echo "==== init batch START $(date -Is) root=$ROOT perf=$PERF_DIR N=$START..$END ===="

stop_ports() {
  local n="$1"
  local base_p2p=51051
  local i p
  # Explicit P2P stop (PID via lsof) before hard fuser kill.
  python3 performance/start_multi_p2p.py --num-parties "$n" --base-port "$base_p2p" --stop >/dev/null 2>&1 || true
  for i in $(seq 1 "$n"); do
    p=$((4432 + i))   # rpo 4433..
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
    p=$((4454 + i))   # rpe 4455..
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
    p=$((base_p2p + i - 1))
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
  done
  # belt-and-suspenders for common range
  for p in $(seq 4433 4442) $(seq 4455 4464) $(seq 51051 51060); do
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
  done
  # Wait until ports are actually free to avoid next-round contention.
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    local busy=0
    for p in $(seq 4433 $((4432 + n))) $(seq 4455 $((4454 + n))) $(seq "$base_p2p" $((base_p2p + n - 1))); do
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
  rm -rf RPE_party* RPO_party* fabric_client_party*
  python3 performance/setup_multi_party.py \
    --num-parties "$N" \
    --transport p2p \
    --p2p-port 51051
  nohup python3 performance/start_multi_p2p.py \
    --num-parties "$N" \
    --base-port 51051 \
    > "$PERF_DIR/logs/p2p_n${N}.log" 2>&1 &
  sleep 3
  if ! python3 performance/performance_test.py \
      --test phase1 \
      --single "$N" \
      --perf-dir "$PERF_DIR"; then
    echo "ERROR: performance_test failed for N=$N" | tee -a "$PERF_DIR/failures.log"
    stop_ports "$N"
    continue
  fi
  # ensure consensus fields present
  python3 - << PY
import json
from pathlib import Path
p = Path("$PERF_DIR") / "test_result_${N}rpes.json"
d = json.loads(p.read_text())
stats = d.get("statistics", {})
print("N=$N t_exchange", stats.get("t_exchange"))
print("N=$N t_join", stats.get("t_join"))
print("N=$N phase2", stats.get("phase2"))
if stats.get("t_exchange", {}).get("count", 0) < 1 and $N >= 1:
    # N=1 should still have t_exchange after self policy send/query
    print("WARN: missing t_exchange stats for N=$N")
PY
  stop_ports "$N"
  sleep 3
done

echo "==== generate summary ===="
python3 performance/performance_test.py \
  --perf-dir "$PERF_DIR" \
  --report-from $(seq "$START" "$END")

echo "==== init batch DONE $(date -Is) ===="
ls -la "$PERF_DIR"/test_result_*rpes.json "$PERF_DIR"/summary_report* 2>/dev/null || true
