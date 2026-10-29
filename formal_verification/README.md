# SRAS ProVerif Formal Verification

The N=3 entry point now executes Stage 1–3, extending commit
`3766338d5301d543434a57fdcb3aea037aea512a`. It includes the new `StrongerSVNE2`
profile, which raises only E2's minimum SVN from V1 to V2. The five properties
Authorization, Agreement, Authenticity, Completeness, and Issuance all hold
under ProVerif 2.05 in the stated twelve-profile model. Stage 1 now performs
the owner/RPE Quote exchange and actual authorization signature checks.

| Entry point | Tested source in `revised-20261027/models/` | Scope |
|---|---|---|
| `sras-n2.pv` | `sras-n2-primary.pv` | N=2 Stage 2, Stage 3 quote checks and certificate issuance |
| `sras-n3.pv` | `sras-n3-stage123r2-primary.pv` | N=3 Stage 1–3, explicit Self RPE/TEE checks, all five properties |
| `sras-n3-ablation.pv` | `sras-n3-no-confirm-primary.pv` | Historical N=3 Stage 2-only confirmation ablation; not extended in this run |

The entry points match these full-query source files. The current N=3
properties were tested individually with the same protocol process and input
domain; their individual files differ only in queries and comments. Original models
are preserved in [`revised-20261027/legacy/models/`](revised-20261027/legacy/models/)
and Git history. The historical ablation also allowed partial input views;
it is different from the single-change ablation published on 2026-10-27.

The current [summary](revised-20261027/reports/stage123r2-SUMMARY.txt),
[exact query/result table](revised-20261027/reports/stage123r2-results-table.csv),
and [reproduction instructions](revised-20261027/reports/stage123r2-REPRODUCE.txt)
document revision r2. The five individual query runs took 36.13 s,
57.89 s, 48.31 s, 47.68 s, and 35.81 s respectively. General,
E2-SVN-specific, and Weak witnesses each contain all three authorization
acceptances, confirmations, and certificate issuances in one execution.
Fourteen auxiliary correspondences also hold. The current 69 model jobs
produced 189 determinate query results, including 29 controlled scenarios,
16 local Stage 1 models and two join comparison models. Four early Quote
scenarios retain all three real authorizations and the exact Evidence-check
prefix; the other 25 controlled scenarios retain the full Stage 2–3 bodies.
Private controls and explicit sender/hardware fault injection are identified
separately from the public-network proofs.
The [second-instructions coverage review](revised-20261027/reports/stage123r2-second-instructions-coverage.txt)
maps requirements to their evidence level. Previously missing targeted checks
are now covered; the original general policy domain remains narrowed by the
later twelve-profile instruction. Optional ablation was not rerun. Earlier
Stage 2–3 and Stage123 r1 evidence remains in local archives; it is not added
again as current evidence in this revision.
The [one-page paper summary](revised-20261027/reports/stage123r2-paper-summary.txt)
states which claims the current results support.
All 69 selected jobs' original model snapshots and logs are included directly,
along with the three joint execution traces in text, DOT and PDF form. The
source audit can check and regenerate the models without Docker or Git.

## Model and scope

The network is public and controlled by a Dolev–Yao adversary. The last party's
owner is malicious, while its RPE still executes the protected protocol.
The model assumes one initialization, a common static configuration, and
exactly two or three protected RPE roles. In the current N=3 model, O1 and O2
execute the full local authorization protocol, while the adversary knows O3's
signing key. Every RPE checks the actual received authorization, including its
own key, policy hash, Self, concrete signer fingerprint, and own attester.
The original N=2 model still treats Stage 1 as an initialization assumption.

The current malicious policy domain has **12 explicit profiles**; honest
parties have concrete configured policies. SVN has three levels and TCB
requirements use finite status sets. This is not a proof for arbitrary
policies, arbitrary N, repeated initialization, or independently configured
membership. See the [current scope audit](revised-20261027/reports/stage123r2-source-audit.json)
and [policy catalog](revised-20261027/models/policy-catalog-stage123r2-p12.json).
The catalog is not a complete abstraction of arbitrary field combinations.
It represents six principal constraint types and typical semantic cases.
There is also no established basis for claiming near-complete combination
coverage: even a slice varying only three minimum SVNs yields eight distinct
successful aggregate vectors, of which the catalog represents three. See the
[enumeration and interpretation](revised-20261027/reports/stage123r2-profile-coverage.txt).
The formerly missing E2-only SVN strengthening is now included; other field
combinations remain outside the catalog. The two honest policies have different Self entries
but the same fixed constraints, as in the requested baseline.

For Stage 1, a private policy constructor with public catalog factories encodes
the finite input domain; the two honest policies are also public. This adds no
allow-list check to the RPE protocol. All RPEs receive arbitrary network
messages and owner verification keys, then perform their actual checks. This
models fourteen complete configurations (two honest policies plus twelve P3
profiles), not arbitrary author-supplied policy fields. Role-to-instance pairs
P1/E1, P2/E2, and P3/E3 are fixed. Self RPE and Self TEE are independently
serialized policy fields, both checked against the role configuration in
Stage 1; a local wrong-SelfTEE control exercises the latter check.
Policies and authentication are public abstractions here;
confidential provisioning and TLS implementations are outside the proofs.

Initial and Evidence Quotes share the hardware key, `rpeQuote` constructor,
and a single hash over the key and a byte string. Keys, nonces and fingerprints
use bytes, so a phase-specific type or hash does not prevent mixing. The
initial Quote service stays available before and after authorization. Stage 3
retains the baseline separate TEE Quote/hardware-key abstraction.

Each RPE verifies peer evidence, associates a quote key with authenticated
policy messages, checks the policy hash and peer TCB, excludes its own key,
and rejects duplicate peer keys before computing the full policy join. Policy
and confirmation signatures abstract authentication under the quote-bound
keys; TLS implementation and channel confidentiality are not proved.

The join produces normalized constraints without retaining source-policy
history. A finite-domain specialization of the canonical fold keeps the
protocol queries tractable; separate algebra and specialization regressions
check it against the generic join semantics over the stated domain.

In N=2 and the new N=3 model, Stage 3 checks the quote signature, entity key and fresh challenge,
measurement, signer, product, SVN, TCB status, and attester. The certificate
signature binds the entity key, issuing RPE key, and H(π*). Real SGX/TCB
collateral validation, certificate consumers, and end-to-end TLS are outside
this symbolic model. Availability against the network adversary is not proved.

## Results and interpretation

| Property | Meaning | Historical N=2 | N=3 Stage 1–3 | Historical N=3 Stage 2 without confirmation |
|---|---|---|---|---|
| Authorization | Acceptance claiming an honest signer follows its real signature for the same key and policy hash | — | true | — |
| Q1 Agreement | Distinct parties that complete hold the same π* | true | true | true |
| Q2 Authenticity | An accepted policy was declared by the corresponding RPE | true | true | true |
| Q3 Completeness | Local completion follows a full policy join | true | true | true |
| Q4 Issuance | Issuance follows satisfaction of the quote checks | true | true | — |

Q1–Q3 retain their original query shapes. Q4 retains its correspondence and
adds the issuer, entity, key, challenge, attributes, policy, and certificate
body to bind the witness to the actual issuance.

The historical confirmation-removal experiment did **not** produce an Agreement violation.
Separate coordination queries reconstructed counterexamples:
a party can complete (and in N=2 issue a compliant certificate) before a peer
has performed its full join. The full models exclude those traces. This
diagnostic does not assert that every peer has already emitted `Confirm`,
and it is neither policy disagreement nor noncompliant issuance. See the
[coordination traces](revised-20261027/reports/coordination-counterexamples.txt).

The historical 2026-10-27 evidence comprises 40 model runs with 127 query results plus seven
isolated primary-query timing runs. All seven primary queries and 19 auxiliary
correspondences hold. Twenty-four rejection scenarios check both a reachable
precondition and rejection at the intended stage. Joint reachability witnesses
place both N=2 completions and legitimate issuances, or all three N=3
completions, in the same execution. No final query is inconclusive.

Those seven isolated primary queries took 0.21–0.32 seconds for N=2 and
1.55–1.77 seconds for N=3 on the recorded host. These are single observations,
not averages or timings for every query within a combined run.
Those N=3 timings covered Stage 2 only. Intermediate Stage 2–3 timings and
development attempts are retained in local archives, separate from the current
dataset. Current
Stage 1–3 timings are listed above; all five main queries completed within
58 seconds each and no current query is inconclusive. Timings are individual
observations, not a controlled comparison of revisions.

* Correspondence `is true`: proved within the stated model.
* Correspondence `is false` with a reconstructed trace: counterexample.
* Reachability output `not event(...) is false`: the event is reachable;
  this is expected for successful execution witnesses, not a security failure.
* `cannot be proved` and timeouts are inconclusive, not attacks.

## Reproduce

Docker and Python 3 (standard library only, for generation/reporting) are
required. The checked-in models are standalone and need no generation before
running. From this directory:

```sh
sudo docker build -t sras-proverif:latest .
sudo docker run --rm --network none sras-proverif:latest proverif -help
```

The Dockerfile pins ProVerif 2.05. The recorded experiment used the restored
`sras-proverif:latest` archive; its exact image identity and package versions
are retained in the logs. Building with the current base image and package
repositories is not guaranteed to reproduce that image byte for byte.

Run an entry point with a read-only source mount:

```sh
sudo docker run --rm --network none -v "$(pwd):/work:ro" -w /work \
  sras-proverif:latest proverif -parse-only sras-n2.pv
sudo docker run --rm --network none -v "$(pwd):/work:ro" -w /work \
  sras-proverif:latest timeout 600 proverif sras-n2.pv
```

Substitute `sras-n3.pv` or `sras-n3-ablation.pv` to run the other entry points.
For the new three-party experiment, use the existing generator and runner:

```sh
cd revised-20261027
python3 stage123_complete.py
python3 stage123_supplement.py
SRAS_TIMEOUT_SECONDS=150 SRAS_MEMORY=2g sh run.sh reproduced-r2-main jobs-stage123r2-main.txt
SRAS_TIMEOUT_SECONDS=150 SRAS_MEMORY=2g sh run.sh reproduced-r2-witness jobs-stage123r2-witness.txt
SRAS_TIMEOUT_SECONDS=30 SRAS_MEMORY=2g SRAS_GRAPHS=0 sh run.sh reproduced-r2-controls jobs-stage123r2-controls.txt
SRAS_TIMEOUT_SECONDS=30 SRAS_MEMORY=1g SRAS_GRAPHS=0 sh run.sh reproduced-r2-local jobs-stage123r2-local.txt
SRAS_TIMEOUT_SECONDS=30 SRAS_MEMORY=1g SRAS_GRAPHS=0 sh run.sh reproduced-r2-tables jobs-stage123r2-control-tables.txt
```

Run the three auxiliary job lists and collect results as described in
the [complete r2 instructions](revised-20261027/reports/stage123r2-REPRODUCE.txt).
Use `stage123_complete.py --install` to update the N=3 entry point. The older
`generate_models.py --stage123` command generates r1 and should not replace it.

For the historical regression suite, choose new output names (existing results
are never overwritten). The runner uses noninteractive `sudo`; authenticate
before invoking it if required by the host:

```sh
sudo -v
cd revised-20261027
sh run.sh reproduced-main jobs.txt
sh run.sh reproduced-primary-times jobs-primary-single.txt
```

The runner saves source hashes, commands, parse and verification logs, exit
statuses, elapsed times, environment metadata, and requested DOT/PDF trace graphs.
Controlled scenarios disable drawing with `SRAS_GRAPHS=0` while retaining
textual trace reconstruction; public execution witnesses retain graphs.
It mounts sources read-only and only the new result directory as writable.
Docker networking is disabled; the modeled ProVerif network remains public.

Check the current experiment's source/log manifest from `revised-20261027`:

```sh
python3 organize_stage123r2_results.py
sha256sum -c SHA256SUMS.stage123r2.public.txt
```

The old `SHA256SUMS.public.txt` is pinned to commit `3766338d530` and must be
checked in that revision, since the generator and runner have now changed.
Use `organize_stage123r2_results.py` for the current source audit; its report
inputs and pinned baseline generator are included, so no unpublished files or
Git database are needed. Original batch `jobs.txt` files retain their recorded
lists; `stage123r2-current-selection.json` selects the 69 published jobs.
The historical `collect_results.py` reads the saved `final-v2` and `primary-single` batches; it does
not run ProVerif or automatically switch to a new run. Current source
generation uses `stage123_complete.py` and `stage123_supplement.py`;
the default `generate_models.py` command is for historical models. If changing
a model, preserve prior evidence and collect new results explicitly. Do not
weaken checks or queries solely to obtain successful results.

## Evidence and history

* [Current three-party summary](revised-20261027/reports/stage123r2-SUMMARY.txt),
  [source audit](revised-20261027/reports/stage123r2-source-audit.json), and
  [machine-readable current results](revised-20261027/reports/stage123r2-results.json).
* [Selected current jobs](revised-20261027/reports/stage123r2-current-selection.json)
  identify the authoritative jobs in `revised-20261027/results/stage123r2-*-20261028/`;
  each job includes its immutable model snapshot, command, logs, timings and traces.
* [Development status summary](revised-20261027/reports/stage123r2-development-summary.json)
  records the unselected attempts. Their raw files, intermediate r1/Stage 2–3
  datasets, and standalone delivery archives remain local. They are excluded
  from this submission's current evidence and do not affect the 189 results.

* [Historical summary](revised-20261027/SUMMARY.txt) and
  [full run instructions](revised-20261027/RUNNING.txt).
* [Exact queries and results](revised-20261027/reports/queries-and-results.txt),
  [CSV table](revised-20261027/reports/results-table.csv), and
  [machine-readable checks](revised-20261027/reports/verification-checks.json).
* [Final raw logs](revised-20261027/results/final-v2/) and
  [isolated primary timings](revised-20261027/results/primary-single/).
* [Source diffs](revised-20261027/diffs/),
  [original models](revised-20261027/legacy/models/), and
  [development timeouts and source snapshots](revised-20261027/results/development/).
* [Restoration baseline](results/restore-20261027/) and
  [older baseline](results/rerun-20260808-1925/) describe the **original**
  models, including the old partial-input ablation. Their findings are
  historical records, not results for the replaced entry points.

The submission adds current source, reports and selected raw evidence only.
Docker images, binary archives, delivery ZIPs and extracted copies, caches,
manuscript/task attachments, abandoned branches and unselected prototype logs
remain local. The current public manifest covers the files required to review
and reproduce the current experiment.
