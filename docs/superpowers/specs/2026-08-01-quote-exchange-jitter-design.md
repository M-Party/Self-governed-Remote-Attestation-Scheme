# Quote Exchange Wall-Clock Jitter Reduction

Date: 2026-08-01

## Problem

Init perf sweeps show `phase2_exchange` variance of ~0.3s–10s across N=4..10 on the same host. Quote generation is stable (~20ms). Spikes concentrate in `phase2_send_local_quote` and/or `phase2_wait_remote_quotes`. N=6 first run timed out; a clean retry was ~0.7s — environment/contention, not N-scaling of crypto.

Root cause in P2P path:

1. `QueryQuoteByIds` blocks a server thread in `wait_for_quotes` (up to ~25s). Concurrent queries starve `SendQuote` handlers → send appears multi-second.
2. Peer fanout opens a new `grpc.insecure_channel` per attempt (connection thrash).
3. Leftover P2P/RPE processes between batch rounds amplify the next N.

## Goals

- Reduce send-path queueing / thrash on the P2P exchange service.
- Keep wait-for-all semantics on the RPE client (poll until complete).
- Expose send vs wait in aggregated statistics and summary CSV/TXT.
- Harden batch cleanup between N (no multi-run median yet — leave variance visible).

## Non-goals

- Per-N repeat + median aggregation.
- Push-based quote notification redesign.
- Fabric transport path changes.
- Changing Quote/attestation security semantics.

## Design

### P2P service (`performance/p2p_quote_exchange.py`)

1. **Non-blocking `QueryQuoteByIds`**: return currently available quotes immediately (partial OK). Do not hold server threads in `wait_for_quotes`.
2. **Channel reuse** in `PeerBroadcaster`: cache per-peer channel/stub under a lock; keep SendQuote retries/timeouts.
3. **Thread pool**: `max_workers = max(20, 4 * (len(peers) + 1))`.
4. **Handler timing logs** on `SendQuote` (wall clock from entry to return) to expose server-side queueing.

### RPE client (`RPE/relying_party_enclave/rpe.py`)

- After non-blocking queries, add a short sleep (~50ms) in the Phase2 wait loop when quotes are incomplete, to avoid busy-spin.

### Reporting (`performance/performance_test.py`)

- Aggregate already-collected `phase2_send_local_quote` / `phase2_wait_remote_quotes` into `statistics` (min/avg/max) and summary CSV/TXT columns.

### Batch harness (`performance/run_init_n1_10.sh`)

- Explicit `start_multi_p2p.py --stop` before/after each N.
- Wait until P2P/RPE/RPO ports are free before starting the next round.

## Acceptance

- Re-run init sweep for N∈{4,5,6,8}: `phase2_exchange` spikes should drop vs prior 6–10s class when environment is clean.
- Summary shows send/wait min/avg/max so residual spikes are attributable.
