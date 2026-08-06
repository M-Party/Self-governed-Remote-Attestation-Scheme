#!/bin/bash
# Overnight Fabric init suite (bt=0.02s, MaxMessageCount=12):
#   1) N=1..10 baseline (no netem)
#   2) RTT delay 20ms, N=2 4 6 8
#   3) RTT delay 50ms, N=2 4 6 8
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_ROOT="${OUT_ROOT:-$ROOT/performance_data/overnight_fabric_${STAMP}}"
BASELINE_DIR="$OUT_ROOT/01_baseline_n1_10"
DELAY20_DIR="$OUT_ROOT/02_delay20ms_n2468"
DELAY50_DIR="$OUT_ROOT/03_delay50ms_n2468"
MASTER_LOG="$OUT_ROOT/overnight.log"
STATUS="$OUT_ROOT/STATUS.txt"

mkdir -p "$BASELINE_DIR" "$DELAY20_DIR" "$DELAY50_DIR" "$OUT_ROOT/logs"
exec > >(tee -a "$MASTER_LOG") 2>&1

clear_netem() {
  sudo -n tc qdisc del dev lo root >/dev/null 2>&1 || true
}

cleanup_parties() {
  local n="${1:-10}"
  python3 performance/start_multi_faric.py --num-parties "$n" --stop >/dev/null 2>&1 || true
  for p in $(seq 4433 4442) $(seq 4455 4464) $(seq 50051 50060); do
    fuser -k -9 "${p}/tcp" 2>/dev/null || true
  done
  rm -rf /tmp/hfc-kvs /tmp/hfc-cvs /tmp/hfc-kvs-* /tmp/hfc-cvs-*
  rm -rf RPE_party* RPO_party* fabric_client_party*
}

write_status() {
  cat >"$STATUS" <<EOT
phase=$1
detail=$2
updated=$(date -Is)
out_root=$OUT_ROOT
EOT
}

summarize_dir() {
  local dir="$1"
  local title="$2"
  local ns="$3"
  python3 - "$dir" "$title" "$ns" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
title = sys.argv[2]
ns = [int(x) for x in sys.argv[3].split()]

def avg_of(d, key):
    vals = [x.get("durations", {}).get(key) for x in d.get("individual_perf", {}).values()]
    vals = [v for v in vals if v is not None]
    return sum(vals) / len(vals) if vals else float("nan")

def g(s, k, f):
    return float((s.get(k) or {}).get(f, 0) or 0)

lines = [title, f"dir={root}", ""]
hdr = (
    f"{'N':>3} | {'P1 avg':>8} | {'Barrier':>8} | {'P2 avg':>8} | {'P2 min':>8} | {'P2 max':>8} | "
    f"{'wait avg':>8} | {'t_ex':>8} | {'t_hpi':>8} | {'Total':>8} | status"
)
lines.append(hdr)
lines.append("-" * len(hdr))
rows = ["N,Phase1_avg,Barrier_avg,Phase2_avg,Phase2_min,Phase2_max,Wait_avg,t_exchange_avg,t_hpi_agree_avg,Total_avg,status"]
ok = 0
for n in ns:
    p = root / f"test_result_{n}rpes.json"
    if not p.exists():
        lines.append(f"{n:3d} | MISSING")
        rows.append(f"{n},,,,,,,,,MISSING")
        continue
    d = json.loads(p.read_text()); s = d["statistics"]
    b = avg_of(d, "pre_phase2_barrier"); h = avg_of(d, "t_hpi_agree")
    lines.append(
        f"{n:3d} | {g(s,'phase1','avg'):8.3f} | {b:8.3f} | {g(s,'phase2','avg'):8.3f} | "
        f"{g(s,'phase2','min'):8.3f} | {g(s,'phase2','max'):8.3f} | "
        f"{g(s,'phase2_wait_remote_quotes','avg'):8.3f} | {g(s,'t_exchange','avg'):8.3f} | "
        f"{h:8.3f} | {g(s,'total','avg'):8.3f} | OK"
    )
    rows.append(
        f"{n},{g(s,'phase1','avg'):.6f},{b:.6f},{g(s,'phase2','avg'):.6f},{g(s,'phase2','min'):.6f},"
        f"{g(s,'phase2','max'):.6f},{g(s,'phase2_wait_remote_quotes','avg'):.6f},"
        f"{g(s,'t_exchange','avg'):.6f},{h:.6f},{g(s,'total','avg'):.6f},OK"
    )
    ok += 1
(root / "summary_with_barrier.txt").write_text("\n".join(lines) + "\n")
(root / "summary_with_barrier.csv").write_text("\n".join(rows) + "\n")
print("\n".join(lines))
print(f"OK_COUNT={ok}/{len(ns)}")
PY
}

on_exit() {
  local code=$?
  echo "==== overnight EXIT code=$code $(date -Is) ===="
  clear_netem
  cleanup_parties 10
  write_status "finished" "exit=$code"
}
trap on_exit EXIT

echo "==== overnight START $(date -Is) ===="
echo "OUT_ROOT=$OUT_ROOT"
echo "config: BatchTimeout=0.02s MaxMessageCount=12"
write_status "starting" "cleanup"

clear_netem
cleanup_parties 10

echo "---- netem smoke verify ----"
if ! python3 performance/run_with_netem_delay.py --delay-ms 20 -- \
  python3 performance/verify_netem_delay.py --count 3; then
  echo "WARN: netem verify failed; delay phases may be invalid"
fi
clear_netem

# Phase 1
write_status "phase1_baseline" "N=1..10"
echo ""
echo "######## PHASE 1: Fabric baseline N=1..10 $(date -Is) ########"
PHASE1_EC=0
if ! RESET_LEDGER=1 bash performance/run_init_fabric_n1_10.sh "$BASELINE_DIR" 1 10; then
  PHASE1_EC=1
fi
cleanup_parties 10
summarize_dir "$BASELINE_DIR" "Fabric baseline (no netem), bt=0.02 mc=12, N=1..10" "1 2 3 4 5 6 7 8 9 10" \
  | tee "$BASELINE_DIR/summary_echo.txt"
python3 performance/performance_test.py --perf-dir "$BASELINE_DIR" --report-from $(seq 1 10) || true

# Phase 2
write_status "phase2_delay20" "N=2 4 6 8"
echo ""
echo "######## PHASE 2: Fabric + netem RTT 20ms N=2,4,6,8 $(date -Is) ########"
PHASE2_EC=0
if ! python3 performance/run_with_netem_delay.py --delay-ms 20 --dev lo -- \
  bash performance/_overnight_sparse_fabric.sh "$DELAY20_DIR" 2 4 6 8; then
  PHASE2_EC=1
fi
clear_netem
cleanup_parties 10
summarize_dir "$DELAY20_DIR" "Fabric + netem RTT 20ms (lo), bt=0.02 mc=12, N=2 4 6 8" "2 4 6 8" \
  | tee "$DELAY20_DIR/summary_echo.txt"
python3 performance/performance_test.py --perf-dir "$DELAY20_DIR" --report-from 2 4 6 8 || true

# Phase 3
write_status "phase3_delay50" "N=2 4 6 8"
echo ""
echo "######## PHASE 3: Fabric + netem RTT 50ms N=2,4,6,8 $(date -Is) ########"
PHASE3_EC=0
if ! python3 performance/run_with_netem_delay.py --delay-ms 50 --dev lo -- \
  bash performance/_overnight_sparse_fabric.sh "$DELAY50_DIR" 2 4 6 8; then
  PHASE3_EC=1
fi
clear_netem
cleanup_parties 10
summarize_dir "$DELAY50_DIR" "Fabric + netem RTT 50ms (lo), bt=0.02 mc=12, N=2 4 6 8" "2 4 6 8" \
  | tee "$DELAY50_DIR/summary_echo.txt"
python3 performance/performance_test.py --perf-dir "$DELAY50_DIR" --report-from 2 4 6 8 || true

# README
python3 - "$OUT_ROOT" "$PHASE1_EC" "$PHASE2_EC" "$PHASE3_EC" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
ecs = [int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])]
parts = []
for name in ["01_baseline_n1_10", "02_delay20ms_n2468", "03_delay50ms_n2468"]:
    p = root / name / "summary_with_barrier.txt"
    parts.append(p.read_text() if p.exists() else f"{name}: MISSING summary\n")
readme = f"""# Overnight Fabric init results

- Config: BatchTimeout=0.02s, MaxMessageCount=12
- Netem: --delay-ms = target RTT on lo (one-way = RTT/2)
- Exit codes: baseline={ecs[0]} delay20={ecs[1]} delay50={ecs[2]}
- Master log: {root / 'overnight.log'}
- Live status: {root / 'STATUS.txt'}

## Dirs

- `01_baseline_n1_10/` — Fabric N=1..10, no injected delay
- `02_delay20ms_n2468/` — Fabric N=2,4,6,8 under 20ms RTT
- `03_delay50ms_n2468/` — Fabric N=2,4,6,8 under 50ms RTT

## Summaries

"""
readme += "\n---\n\n".join(parts)
(root / "README.md").write_text(readme)
print(readme)
PY

OVERALL=0
if (( PHASE1_EC != 0 || PHASE2_EC != 0 || PHASE3_EC != 0 )); then
  OVERALL=1
fi
echo "==== overnight ALL PHASES DONE overall=$OVERALL $(date -Is) ===="
write_status "done" "overall=$OVERALL phase1=$PHASE1_EC phase2=$PHASE2_EC phase3=$PHASE3_EC"
ln -sfn "$OUT_ROOT" "$ROOT/performance_data/overnight_fabric_latest"
exit "$OVERALL"
