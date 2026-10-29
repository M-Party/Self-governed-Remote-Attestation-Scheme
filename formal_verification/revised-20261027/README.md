# Current SRAS Experiment: N=3, Stage 1–3

This directory contains the **current experiment**, not another historical
result set. Its name comes from the date the revision directory was first
created; it was reused for the latest Stage 1–3 work.

There is one current result set: **69 selected jobs, 189 determinate queries**.
Authorization, Agreement, Authenticity, Completeness and Issuance all hold in
the stated twelve-profile model. Older result tables, summaries and logs have
been removed from this branch and remain available in Git history.

Start here:

- [Result summary](reports/stage123r2-SUMMARY.txt).
- [Exact queries, results, model hashes, times and original log paths](reports/stage123r2-results-table.csv).
- [Complete reproduction instructions](reports/stage123r2-REPRODUCE.txt).
- [Selected current jobs](reports/stage123r2-current-selection.json).
- [Model scope and source audit](reports/stage123r2-source-audit.json).

| Location | Contents |
|---|---|
| `models/` | Full models, joint queries, policy catalog and join checks |
| `queries/` | Five primary and fourteen auxiliary query models |
| `scenarios/` | Current targeted controls and local guard checks |
| `results/` | Selected jobs' original output, frozen models, commands, times and environment records |
| `reports/` | Current result tables, summaries, scope and evidence indexes |
| `diffs/` | Changes from the stated baseline to the current implementation |
| `legacy/generate_models-3766338.py` | Pinned baseline source used by the audit; not an old result set |

The selected jobs are authoritative even when a recorded batch name contains
`pilot`: batch names are preserved for provenance, and the selection specifies
the completed models matching the current source. Unselected prototypes are
not included as current evidence.

All three public joint execution witnesses contain three authorization
acceptances, three confirmations and three compliant certificate issuances
in a single execution:

| Actual P3 profile | Original output | Trace |
|---|---|---|
| PermissiveRpeTCB | [Log](results/stage123r2-witness-20261028/sras-n3-stage123r2-reachability/output.log) | [PDF](results/stage123r2-witness-20261028/sras-n3-stage123r2-reachability/graphs/trace1.pdf) |
| StrongerSVNE2 | [Log](results/stage123r2-witness-20261028/sras-n3-stage123r2-reachability-profile12/output.log) | [PDF](results/stage123r2-witness-20261028/sras-n3-stage123r2-reachability-profile12/graphs/trace1.pdf) |
| Weak | [Log](results/stage123r2-witness-20261028/sras-n3-stage123r2-reachability-weak/output.log) | [PDF](results/stage123r2-witness-20261028/sras-n3-stage123r2-reachability-weak/graphs/trace1.pdf) |

From this directory, verify the saved evidence and regenerate the models
without Docker or a Git database:

```sh
python3 organize_stage123r2_results.py
sha256sum -c SHA256SUMS.stage123r2.public.txt
```

Rerunning ProVerif itself requires the environment described in the
[reproduction instructions](reports/stage123r2-REPRODUCE.txt).
