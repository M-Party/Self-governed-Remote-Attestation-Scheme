# SRAS Formal Verification — Current Results

The current experiment is **N=3, Stage 1–3, with 12 policy profiles**.
This branch presents one current result set: 69 selected model jobs and
189 determinate query results under ProVerif 2.05.

Start with the [current experiment directory](revised-20261027/),
[result summary](revised-20261027/reports/stage123r2-SUMMARY.txt),
[exact query/result table](revised-20261027/reports/stage123r2-results-table.csv),
and [reproduction instructions](revised-20261027/reports/stage123r2-REPRODUCE.txt).

`revised-20261027` is the directory name established when the revision began.
It has been reused for the current experiment; it is not another result set.
Old summaries, result tables and logs have been removed from this branch.
Their contents remain available in Git history and in a local backup.

## Current results

| Property | Result | Individual run time |
|---|---|---:|
| Authorization | proved | 36.13 s |
| Agreement | proved | 57.89 s |
| Authenticity | proved | 48.31 s |
| Completeness | proved | 47.68 s |
| Issuance | proved | 35.81 s |

The five queries use the same protocol process, input domain and corruption
configuration. Fourteen auxiliary correspondences also hold. Three reconstructed
joint traces each contain all three RPEs' authorization acceptance, confirmation
and compliant instance issuance. Their actual P3 profiles are
`PermissiveRpeTCB`, `StrongerSVNE2` and `Weak`.

The result table includes every query, its interpretation, source hash, timing
scope and original log. A reachability result of `not event(...) is false`
with a reconstructed trace means the execution is reachable; it is not an
agreement violation. Timings are individual verifier observations, not protocol
latencies or averages.

## Model and scope

The public network is controlled by a Dolev–Yao adversary. O1 and O2 are honest,
O3's signing key is public, and all three RPEs execute protected protocol code.
The model has one initialization, common static membership, two fixed honest
policies and twelve complete P3 profiles. These represent major policy fields
and typical combinations; proofs apply to this stated domain and configuration.

Stage 1 actually performs the owner challenge, initial Quote verification,
authorization signature and RPE checks of key, policy hash, signer fingerprint,
Self RPE/TEE and own attester. The same authorized key–policy state continues
through Stage 2 collection, normalized join and confirmation, then Stage 3
instance appraisal and certificate issuance.

Initial and Evidence Quotes share the hardware key, `rpeQuote` constructor and
hash payload shape. Stage 3 retains the baseline separate TEE Quote/hardware-key
abstraction. TLS, real collateral implementation, arbitrary membership or
corruption configurations, repeated initialization and arbitrary N are outside
the result. See the [scope audit](revised-20261027/reports/stage123r2-source-audit.json)
and [policy catalog](revised-20261027/models/policy-catalog-stage123r2-p12.json).

The 29 targeted controlled scenarios and local guard/algebra checks are
identified separately from the public-network proofs. Four early Quote controls
keep three real authorizations and the exact Evidence-check prefix; the other
25 retain the full Stage 2–3 bodies. Fault injection is explicitly classified.

## Verify or reproduce

Check the saved evidence and regenerate every current model without Docker or Git:

```sh
cd revised-20261027
python3 organize_stage123r2_results.py
sha256sum -c SHA256SUMS.stage123r2.public.txt
```

The pinned baseline generator and report inputs are included. The selection in
`reports/stage123r2-current-selection.json` defines the 69 current jobs; original
batch `jobs.txt` files retain their recorded lists. Current original logs and
model snapshots are in the selected `results/stage123r2-*-20261028/` jobs.

To rerun ProVerif, Docker and Python 3 are required. From `formal_verification/`:

```sh
sudo docker build -t sras-proverif:latest .
cd revised-20261027
python3 stage123_complete.py
python3 stage123_supplement.py
SRAS_TIMEOUT_SECONDS=150 SRAS_MEMORY=2g sh run.sh reproduced-r2-main jobs-stage123r2-main.txt
```

The [full instructions](revised-20261027/reports/stage123r2-REPRODUCE.txt) give
all auxiliary, witness and control commands. Sources are mounted read-only;
Docker networking is disabled while the modeled network remains public.
The Dockerfile pins ProVerif 2.05; exact recorded image/version information is
saved with each batch. A rebuilt image need not be byte-identical to that image.

`sras-n3.pv` is the current entry point. `sras-n2.pv` and `sras-n3-ablation.pv`
are retained historical source references, not additional current results;
this round did not rerun the optional confirmation ablation.

## Historical experiments

Older results are accessed through their original commits, rather than displayed
alongside the current result table:

- [Original model/results at cca9416](https://github.com/M-Party/Self-governed-Remote-Attestation-Scheme/tree/cca94160d09e2ffe75b1f0b5c23c43980ae4a2be/formal_verification).
- [Stage 2 / earlier N=2 evidence at 3766338](https://github.com/M-Party/Self-governed-Remote-Attestation-Scheme/tree/3766338d5301d543434a57fdcb3aea037aea512a/formal_verification).

The single file `revised-20261027/legacy/generate_models-3766338.py` is a pinned
source comparison dependency used by the current audit, not an old result set.
Docker images, ZIPs, extracted delivery copies, task attachments, caches and local
historical backups are excluded from this branch's experiment submission.
