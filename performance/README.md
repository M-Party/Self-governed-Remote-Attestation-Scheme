# SRAS Performance Tests

This guide covers Stage **1 / 2 / 3** latency experiments and the FT-oriented
**Q1 / Q2** studies. For a short entry point in the main demo guide, see
[README.md — SRAS Stage 1 / 2 / 3](../README.md#sras-stage-1--2--3-performance-tests).

| Stage | Script | Typical output |
|------:|---|---|
| 1–2 init (P2P) | `run_init_n1_10.sh`, `performance_test.py` | `test_result_<N>rpes.json` |
| 1–2 init (Fabric) | `run_init_fabric_n1_10.sh` | same |
| 1–2 + NetEm | `run_with_netem_delay.py --delay-ms <RTT>` | wrap either batch above |
| 3 CE auth | `phase3_performance_test.py` (`--ce-first --total-time` or `--repeat`) | `summary_report_*` / `state_update_report_*` |
| Q1 FT overhead | see below | `state_update_report.*` |
| Q2 FT recovery | `q2_ft_recovery_test.py` | `q2_ft_recovery_report.*` |

NetEm note: `--delay-ms` is **target RTT** on `lo` (one-way = RTT/2).

---

# Q1: SRAS-FT Attestation Overhead

## Research question

**Q1: What is the attestation overhead introduced by SRAS-FT?**

Compare baseline SRAS vs SRAS-FT: before TEE certificate issuance
(`generate_ce_certificate`), how much total latency increases after adding
**state propagation** and **echo verification**.

---

## Experiment design

| Group | RPE config | Extra steps before issuance | Metrics |
|------|------------|-----------------------------|---------|
| **Baseline (plain SRAS)** | `ft.enabled = false` | No FT propagation | `attestation_overhead` (≈ TEE quote verify) |
| **SRAS-FT** | `ft.enabled = true`, peers configured | State propagation + echo quorum | `attestation_overhead`, `ft_state_propagation`, breakdown columns |

Use the **same** party count, P2P transport, and CE count; only the FT switch
differs. Prefer **≥5** successful CE authentications per group and report averages.

---

## Prerequisites

1. Build RPE / RPO / CE on an SGX machine (including SRAS-FT code).
2. Configure **collaterals** and **QEID** for each party as in the main README.
3. For local multi-party loopback tests, prefer **P2P** as the Phase 2 quote
   exchange path (no Fabric network required).

---

## 1. Environment setup

### 1.1 Build (template binaries once)

```bash
cd RPE && ./startup.sh build
cd ../RPO && ./startup.sh build
cd ../CE  && ./startup.sh build
```

### 1.2 Create multi-party directories

**SRAS-FT group** (FT on):

```bash
python3 performance/setup_multi_party.py \
  --num-parties 5 \
  --transport p2p \
  --p2p-port 51051 \
  --ft-enabled
```

**Baseline group** (FT off; omit `--ft-enabled`):

```bash
python3 performance/setup_multi_party.py \
  --num-parties 5 \
  --transport p2p \
  --p2p-port 51051
```

This creates `RPO_party*`, `RPE_party*`, `fabric_client_party*` (under P2P the
Fabric client is unused in Phase 2 but directories are still created) and
`policies-N.json`.

### 1.3 Configure CEs (issuing RPE defaults to RPE_party1 / port 4455)

```bash
python3 performance/setup_multi_ce.py \
  --num-ces 3 \
  --rpe-address 127.0.0.1 \
  --rpe-port 4455
```

Creates `CE_party1` … `CE_party3`, all requesting certificates from **rpe-1**.

---

## 2. Startup order (important)

Start in the order below and **wait until every RPE finishes Phase 1 + Phase 2**
before triggering CE authentication:

```bash
# Terminal 1: P2P quote exchange
python3 performance/start_multi_p2p.py --num-parties 5 --base-port 51051

# Terminal 2: RPO
python3 performance/start_multi_rpo.py --num-parties 5

# Terminal 3: RPE (blocks while running)
python3 performance/start_multi_rpe.py --num-parties 5
```

**Ready check** (example: RPE_party1):

```bash
grep -E "Phase two|quorum|Phase 3|pre_init_ready" RPE_party1/logs/rpe_party1.log | tail -20
```

Confirm all 5 RPEs completed Phase 2 and are waiting in Phase 3 before continuing.

> **Common pitfall:** Connecting CEs before RPE / P2P are ready yields
> `quorum not reached`, `DEADLINE_EXCEEDED`, CE-side `Invalid certificate length: 0`,
> and repeated retries. Always wait for Phase 2 to finish.

---

## 3. Collect performance data

### 3.1 Start the collector first (`--repeat` mode)

Start **before** triggering CE auth; the script blocks until enough new
authentications arrive:

```bash
# SRAS-FT example
python3 performance/phase3_performance_test.py \
  --repeat 5 \
  --perf-dir performance_data/q1_ft_n5 \
  --rpe-dir RPE_party1
```

```bash
# Baseline example (different output directory)
python3 performance/phase3_performance_test.py \
  --repeat 5 \
  --perf-dir performance_data/q1_baseline_n5 \
  --rpe-dir RPE_party1
```

**Semantics of `--repeat N`:**

- Collect **N new CE authentications** in total (regardless of how many CEs
  start at once).
- Does **not** clear historical RPE perf data; records `baseline_count` at start
  and waits until total count reaches `baseline_count + N`, then reports only
  the new N entries.
- Default input: `RPE_party1/performance_data/rpe_phase3_perf_rpe-1.json`;
  override the issuing RPE with `--rpe-dir`.

### 3.2 Then trigger CE authentication

In another terminal:

```bash
python3 performance/start_multi_ce.py --num-parties 3
```

Or manually run `./startup.sh start` inside each `CE_party*`. Each successful
auth to RPE1 appends one record to the issuing RPE perf JSON.

When N records are collected, the script exits and writes the report.

---

## 4. Output reports

Files under `--perf-dir`:

| File | Description |
|------|-------------|
| `state_update_report.txt` | Human-readable summary + breakdown table |
| `state_update_report.csv` | Tabular data |
| `state_update_report.xlsx` | Excel (requires `openpyxl`) |
| `state_update_report.json` | Full raw payload |

### Breakdown columns

One row = one CE authentication:

| Column | Meaning |
|--------|---------|
| `counter` | FT attestation counter |
| `ce_id` | CE identity |
| `bottleneck_peer` | Peer with largest `rpc + verify_echo` in this auth (same-peer values; do not mix MAXes across peers) |
| `attestation_overhead` | TEE quote verify + state broadcast (echo wait) + echo verification (**excludes** cert issuance) |
| `tee_quote_verify` | CE DCAP quote verification (`stage3_native_quote_verification`, before FT) |
| `state_broadcast_echo_wait` | gRPC RTT of `StateUpdate` to the bottleneck peer (**includes** network + remote processing) |
| `remote.veri+record` | Remote `verify_state_signature + record_state` (**already inside** `state_broadcast_echo_wait`; do not add again) |
| `echo_verification` | Local echo-signature verify after RPC returns (serial after state broadcast) |

### Timing boundaries (issuing RPE)

```
ce_auth_start
  ├─ perform_handshake + verify_peer     → quote_verify
  ├─ get_ce_info + verify_ce_body      → policy (usually near 0)
  ├─ propagate_attestation_state()       → ft_state_propagation / breakdown
  │     ├─ local sign state + echo
  │     ├─ rpc(incl.remote.veri+record)  → parallel per peer; take bottleneck
  │     └─ verify_echo                   → local echo verify after RPC returns
  ├─ generate_ce_certificate()         → counted in end-to-end auth_duration only
  └─ send_ce_cert()
ce_auth_end                              → end-to-end auth_duration
attestation_overhead                     → tee_quote_verify + state_broadcast_echo_wait + echo_verification
```

### How to compute Q1 conclusions

- **FT extra cost (wall-clock):** compare mean `ft_state_propagation_duration`;
  baseline should be 0 / absent.
- **FT share of `attestation_overhead`:**
  `avg(state_broadcast_echo_wait + echo_verification)` or related
  `ft_state_propagation` breakdown (FT group only).
- **Detail:** use avg/min/max of `rpc(incl.remote.veri+record)` and `verify_echo`
  in the breakdown table.

---

## 5. Compare Baseline vs SRAS-FT

1. Finish both groups → `performance_data/q1_baseline_n5/` and
   `performance_data/q1_ft_n5/`.
2. Compare Summaries in `state_update_report.txt`, or CSV/Excel columns such as
   `attestation_overhead` and `tee_quote_verify`.
3. **FT overhead ≈ mean(FT `attestation_overhead`) − mean(Baseline
   `attestation_overhead`)** (same CE count, party count, and network conditions;
   baseline is mostly quote verify).

To keep a raw perf snapshot for later recomputation:

```bash
cp RPE_party1/performance_data/rpe_phase3_perf_rpe-1.json \
   performance_data/q1_ft_n5/rpe_phase3_perf_snapshot.json
```

---

## 6. Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| CE fails several times before success | FT quorum not met; RPE refuses issuance | Confirm all RPEs finished Phase 2; check `RPE_party1/logs/rpe_party1.log` for `quorum reached` |
| `DEADLINE_EXCEEDED` | FT gRPC timeout to a peer (default 3s) | Check that peer’s `RPE_party*/logs/` for `StateUpdate accepted` |
| `invalid echo: signature verification failed` | Peer public key / signing key mismatch | Re-run setup + full Phase 2; do not mix stale `RPE_party*` dirs |
| Collector times out | Not enough successful CE auths | Restart CEs or raise `--repeat` only after CEs can reach RPE |
| Breakdown columns are N/A | Perf JSON lacks `ft_state_propagation_timings` | Confirm FT-enabled RPE build and that this auth ran propagation |

---

## 7. Stop services

```bash
python3 performance/start_multi_ce.py --num-parties 3    # Ctrl+C to stop CEs
python3 performance/start_multi_rpe.py --num-parties 5 --stop
python3 performance/start_multi_rpo.py --num-parties 5 --stop
python3 performance/start_multi_p2p.py --num-parties 5 --stop
```

---

## Related scripts

| Script | Role |
|--------|------|
| `setup_multi_party.py` | Copy/configure multi-party RPO/RPE (`--ft-enabled` toggles FT) |
| `setup_multi_ce.py` | Copy/configure multi CE |
| `start_multi_p2p.py` | Start P2P quote exchange |
| `start_multi_rpo.py` | Start multi RPO |
| `start_multi_rpe.py` | Start multi RPE |
| `start_multi_ce.py` | Start multi CE |
| `phase3_performance_test.py` | Phase 3 performance; Q1 uses `--repeat` |
| `q2_ft_recovery_test.py` | Q2 recovery collection + report |

Raw Stage 3 perf source:
`RPE_party1/performance_data/rpe_phase3_perf_rpe-1.json`
(written by `RPE/relying_party_enclave/rpe.py`).

---

# Q2: Failed-RPE Recovery Latency

## Research question

**Q2: How efficiently can SRAS-FT recover a failed RPE?**

After crash/restart, measure how long the recovering RPE spends on:
Recovery query → Evidence Quote verification → signed-state verification →
select max ACj (**primary Q2 metric `total_recovery_ms` ends here**). After
quorum, the RPE may still collect/verify remaining peer responses (slow-peer
timeout is WARNING only) and refresh peer public keys; then it generates a new
quote and broadcasts EvidenceUpdate (not included in `total_recovery_ms`).

Stacked-bar fields (ms):

`recovery_query` | `evidence_quote_verification` | `signed_state_verification` |
`counter_selection` | `new_quote_generation` + `new_quote_broadcast`
(the last two are reference-only and excluded from Total)

## Prerequisites

1. Multi-party FT stack is healthy and **some CE authentications already ran**
   (peers recorded the failed RPE’s state via `StateUpdate`).
2. The recovering RPE has **`expt_cache.json`** (written after a normal first startup).
3. **Do not** use `start_multi_rpe.py --stop` to simulate crash — it deletes
   `expt_cache.json`.

## Collection (`--repeat` mode)

Start the collector first, then kill + restart once per repeat:

```bash
python3 performance/q2_ft_recovery_test.py \
  --repeat 3 \
  --rpe-dir RPE_party1 \
  --perf-dir performance_data/q2_n5 \
  --label n5
```

Per repeat:

```bash
# Simulate crash (example: kill RPE_party1 port; do NOT use start_multi_rpe --stop)
kill $(lsof -ti :4455)

# Restart recovering RPE (runs recovery and writes perf JSON)
cd RPE_party1 && ./startup.sh start
```

The collector:

- Watches `RPE_party1/performance_data/rpe_ft_recovery_perf_*.json`
- Snapshots each recovery into `performance_data/q2_n5/recovery_runs/run_XXXX.json`
- Writes the report after N recoveries

## Outputs

| File | Description |
|------|-------------|
| `recovery_runs/run_*.json` | Per-recovery snapshot |
| `q2_recovery_session.json` | Session metadata + raw results |
| `q2_ft_recovery_report.{txt,csv,json}` | Aggregate (avg over N runs) |

## Report-only mode

Aggregate across existing directories for different N (e.g. 2/4/8):

```bash
python3 performance/q2_ft_recovery_test.py \
  --input n3=RPE_party1/performance_data \
  --input n5=RPE_party5/performance_data \
  --output-dir performance_data/q2
```

Or from a collected `--perf-dir`:

```bash
python3 performance/q2_ft_recovery_test.py \
  --report-only \
  --perf-dir performance_data/q2_n5 \
  --label n5
```

## Metric notes

- `new_quote_broadcast_ms`: only the **non-blocking** EvidenceUpdate dispatch;
  does not wait for peer ACKs.
- `evidence_quote_verification_ms` / `signed_state_verification_ms`: **sum** over
  valid quorum responses, not single-peer max.

Raw recovery perf path:
`RPE_partyX/performance_data/rpe_ft_recovery_perf_{rpe_id}.json`
(overwritten each recovery; the collector snapshots copies).
