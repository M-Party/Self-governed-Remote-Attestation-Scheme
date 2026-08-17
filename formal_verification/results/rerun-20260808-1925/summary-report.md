# SRAS ProVerif Verification Report

## Environment

- ProVerif: 2.05
- Image: `sras-proverif`
- Models: current host files mounted read-only at `/work`
- Per-run timeout: 600 seconds

## Primary Results

| Model | Query | Result | Runtime (s) | Exit |
|---|---|---|---:|---:|
| `sras-n2.pv` | Q1 cross-party agreement | is true | 0.15 | 0 |
| `sras-n2.pv` | Q2 policy authenticity | is true | 0.15 | 0 |
| `sras-n2.pv` | Q3 Confirm implies FullJoin | is true | 0.15 | 0 |
| `sras-n2.pv` | Q4 issuance compliance | is true | 0.15 | 0 |
| `sras-n3.pv` | Q1 cross-party agreement | is true | 0.05 | 0 |
| `sras-n3.pv` | Q2 policy authenticity | is true | 0.05 | 0 |
| `sras-n3.pv` | Q3 Confirm implies FullJoin | is true | 0.05 | 0 |
| `sras-n3-ablation.pv` | Q1 cross-party agreement | is false | 0.01 | 0 |
| `sras-n3-ablation.pv` | Q2 policy authenticity | is true | 0.01 | 0 |

All three models pass `proverif -parse-only`. No run timed out and no query
returned `cannot be proved`.

## Non-vacuity Checks

Temporary diagnostic copies added reachability queries without modifying the
primary models. In ProVerif output, `not event(...) is false` means the event is
reachable.

- N=3: Confirm is reachable for P1, P2, and P3; P1 and P2 can Confirm in the
  same execution.
- N=3 ablation: Confirm is reachable for P1, P2, and P3; P2 and P3 can Confirm
  in the same execution.

Therefore the N=3 agreement proof is non-vacuous, and the ablation disagreement
is reachable.

## Ablation Attack

ProVerif reconstructed an executable trace and reported:

```text
A trace has been found.
RESULT event(Confirm(a,x)) && event(Confirm(b,y)) && a != b ==> x = y is false.
```

The trace contains P2 confirming a ternary full-view policy and P3 confirming a
binary partial-view policy. These consensus policies differ. The complete text
is in `attack-trace-sras-n3-ablation.txt`; `trace-ablation/trace1.dot` and
`trace-ablation/trace1.pdf` preserve the graph.

## SHA-256

| Artifact | SHA-256 |
|---|---|
| `sras-n2.pv` | `131f65996ec5c9b5f7e3325c14837efc101f8d6e410073fa097da99fbb6e5a40` |
| `sras-n3.pv` | `3ebbb6ccdac49f5b7e91978f54ccc84072724559a82a32b1faf461a1a3537ca0` |
| `sras-n3-ablation.pv` | `f9175a50ecc099ecad98edefb7f270c75b8c16c336754412ff79133aeab35e50` |
| `Dockerfile` | `18170fa0cf66dd2fd5d6e69d6530affc55037caaad708b089981d054a9494467` |

## Evidence Files

- `results-sras-n2.txt`
- `results-sras-n3.txt`
- `results-sras-n3-ablation.txt`
- `attack-trace-sras-n3-ablation.txt`
- `trace-ablation/trace1.dot`
- `trace-ablation/trace1.pdf`
- `results-sras-n3-reachability-current.txt`
- `results-sras-n3-ablation-reachability-current.txt`
- `proverif-version.txt`
