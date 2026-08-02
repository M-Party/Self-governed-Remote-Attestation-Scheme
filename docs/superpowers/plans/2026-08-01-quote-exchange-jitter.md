# Plan: Quote Exchange Jitter Reduction

## Files
- `performance/p2p_quote_exchange.py` — non-blocking QueryQuoteByIds, channel reuse, larger thread pool, SendQuote timing logs
- `RPE/relying_party_enclave/rpe.py` — 50ms poll sleep for quote/policy wait loops
- `performance/performance_test.py` — aggregate/report send vs wait
- `performance/run_init_n1_10.sh` — explicit P2P stop + wait-for-ports-free
- `docs/superpowers/specs/2026-08-01-quote-exchange-jitter-design.md`

## Done
Implementation landed in-repo. Next: rebuild/setup parties and re-run init N=4,5,6,8 (or full 1..10) to validate spike reduction.
