# SRAS ProVerif Formal Verification

This directory contains symbolic models of SRAS mutual attestation and
consensus-policy negotiation, verified with [ProVerif](https://proverif.inria.fr/)
2.05 under a Dolev–Yao network adversary.

## What is modeled

| File | Scope | Threat sketch |
|---|---|---|
| `sras-n2.pv` | N=2 full Stage 2 + light Stage 3 issuance | P2’s owner is corrupted (chooses `rho2`); RPE code still runs honestly |
| `sras-n3.pv` | N=3 symmetric full views + H(π*) confirmation | P3’s owner is corrupted (chooses `rho3`) |
| `sras-n3-ablation.pv` | N=3 asymmetric views, **no** confirmation round | Same corruption; intended to break agreement |

Honest parties use identity pin `Any` on the success path so `joinid` can
complete. Conflicting `exact(m)` / `exact(m')` still abort when they appear
(e.g. in an adversary-chosen policy). Agreement queries are about `Confirm`
events, not about forced join failure.

Protocol sketch (each RPE):

1. Declare local policy `rho` and emit a signed Evidence Quote binding
   owner, RPE public key, and `H(rho)` (`hbind` / `hpol` are abstract hashes).
2. Collect peers’ quotes, exchange full policies, accept only if
   `H(rho)` matches the quote hash.
3. Join identity pins with `joinid`, build consensus `π*` (`mkstar` / `mkstar3`).
4. Confirmation round: exchange `H(π*)` and emit `Confirm` (omitted in ablation).
5. N=2 only: light Stage 3 quote check and certificate issuance events.

## Security queries

| Id | Property (informal) | ProVerif shape |
|---|---|---|
| Q1 | Agreement | If two distinct parties `Confirm`, they hold the same `π*` |
| Q2 | Policy authenticity | `PolicyAccepted(a,b,r)` implies `PolicyDeclared(b,r)` |
| Q3 | Join completeness | `Confirm(a,x)` implies `FullJoin(a,x)` |
| Q4 | Issuance compliance (N=2) | `CertIssued` implies `QuoteSatisfied` |

Interpretation of ProVerif `RESULT` lines:

- `is true` — property proved in the model
- `is false` — attack found (look for `A trace has been found.`)
- `cannot be proved` — inconclusive (Horn over-approx / incomplete); not a
  reconstructed attack by itself

## Method

1. Build a reproducible ProVerif 2.05 environment (`Dockerfile` → image
   `sras-proverif`; ProVerif is installed via `opam`, not from the local
   `proverifbin2.05.tar.gz` tarball, which is gitignored).
2. Mount this directory read-only at `/work` so the container always reads the
   host models.
3. Run `proverif -parse-only` on each model, then `timeout 600 proverif <model>`.
4. On `is false`, keep the full textual derivation and optionally regenerate
   graphs with `proverif -graph <dir> <model>` (needs a writable mount for
   the graph directory).
5. Record stdout, wall-clock time, and exit status under `results/`.

Do not weaken queries or protocol events solely to obtain green results.
If a modeling fix is required (syntax, joinability of default pins), document
root cause and semantic impact first.

## Environment setup

### Prerequisites

- Docker with permission to run containers (`docker` or `sudo docker`)
- This repository checkout

### Build the image

```bash
cd formal_verification
sudo docker build -t sras-proverif .
sudo docker run --rm sras-proverif proverif -help | head
```

Expected: ProVerif 2.05 help banner.

## Verification steps

All commands below assume:

```bash
cd /path/to/SRAS/formal_verification
```

### 1. Parse-only (all models)

```bash
for m in sras-n2.pv sras-n3.pv sras-n3-ablation.pv; do
  echo "==== parse-only $m ===="
  sudo docker run --rm -v "$(pwd):/work:ro" -w /work sras-proverif \
    proverif -parse-only "$m"
done
```

Silent exit status `0` means the model parsed.

### 2. Full verification

```bash
mkdir -p results/manual
for m in sras-n2.pv sras-n3.pv sras-n3-ablation.pv; do
  base=${m%.pv}
  echo "==== proverif $m ===="
  /usr/bin/time -f 'elapsed_seconds=%e exit_status=%x' \
    -o "results/manual/time-${base}.txt" \
    sudo timeout 600 docker run --rm -v "$(pwd):/work:ro" -w /work sras-proverif \
      proverif "$m" \
      >"results/manual/results-${base}.txt" 2>&1
  echo $? >"results/manual/exit-${base}.txt"
  grep -E '^RESULT |^Query |Verification summary|A trace has been found' \
    "results/manual/results-${base}.txt" || true
done
```

### 3. Attack graphs (when a query is false)

Example for the ablation disagreement:

```bash
mkdir -p results/manual/trace-ablation
sudo timeout 600 docker run --rm \
  -v "$(pwd):/work:ro" \
  -v "$(pwd)/results/manual/trace-ablation:/graph:rw" \
  -w /work sras-proverif \
  proverif -graph /graph sras-n3-ablation.pv \
  >results/manual/results-graph-ablation.txt 2>&1
```

Produces `trace*.dot` (and `trace*.pdf` if Graphviz succeeds inside the image).
Root `.gitignore` ignores `*.pdf`; keep the `.dot` in git if desired.

### 4. Optional non-vacuity check

To ensure `Confirm` is reachable (so agreement `true` is not vacuous), add
temporary reachability queries such as:

```text
query x: polstar; event(Confirm(P1, x)).
```

In ProVerif output, `not event(...) is false` means the event **is** reachable.
Do this in a separate copy; do not replace primary Q1–Q4 in the main models.

## Expected results (reference)

Latest checked rerun: `results/rerun-20260808-1925/summary-report.md`.

| Model | Q1 | Q2 | Q3 | Q4 |
|---|---|---|---|---|
| `sras-n2.pv` | true | true | true | true |
| `sras-n3.pv` | true | true | true | — |
| `sras-n3-ablation.pv` | **false** (reconstructed trace) | true | — | — |

Ablation Q1 false corresponds to asymmetric views without H(π*) confirmation:
one party confirms a ternary `mkstar3` policy while another confirms a binary
`mkstar2` policy.

## Layout

```text
formal_verification/
  Dockerfile              # opam + ProVerif 2.05 image
  .dockerignore
  .gitignore              # ignores local proverifbin*.tar.gz
  README.md               # this file
  sras-n2.pv
  sras-n3.pv
  sras-n3-ablation.pv
  results/                # verification evidence
```

## Notes

- Channel `net` is public: every `in`/`out` is subject to the network adversary.
- `hpol` / `hbind` / `hstar` are abstract hash constructors (no rewrite body).
- `[precise]` on adversarial policy inputs must be written as
  `in(net, rho: policy) [precise];` (annotation outside the type).
- Prefer citing non-injective authenticity for Q2; injective authenticity can
  fail simply because one declaration is accepted by multiple RPEs (fan-out).
