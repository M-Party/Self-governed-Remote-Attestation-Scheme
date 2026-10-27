# SRAS ProVerif Formal Verification

The current entry-point models are the revised models verified with ProVerif
2.05 on 2026-10-27. They preserve Agreement, Authenticity, Completeness, and
Issuance as the four primary property families and make the modeled Stage 2
and Stage 3 checks explicit.

| Entry point | Tested source in `revised-20261027/models/` | Scope |
|---|---|---|
| `sras-n2.pv` | `sras-n2-primary.pv` | N=2 Stage 2, Stage 3 quote checks and certificate issuance |
| `sras-n3.pv` | `sras-n3-primary.pv` | N=3 Stage 2 with complete input collection and confirmation |
| `sras-n3-ablation.pv` | `sras-n3-no-confirm-primary.pv` | Same N=3 model with only confirmation communication and waiting removed |

The entry points are byte-identical to these tested sources. Original models
are preserved in [`revised-20261027/legacy/models/`](revised-20261027/legacy/models/)
and Git history. The historical ablation also allowed partial input views;
it is different from the current single-change ablation.

## Model and scope

The network is public and controlled by a Dolev–Yao adversary. The last party's
owner is malicious, while its RPE still executes the protected protocol.
The model assumes one initialization, a common static configuration, and
exactly two or three protected RPE roles. Stage 1 local authorization and
valid self signer/attester attributes are initialization assumptions.

The malicious owner chooses from **11 explicit policy profiles**; honest
parties have concrete configured policies. SVN has three levels and TCB
requirements use finite status sets. This is not a proof for arbitrary
policies, arbitrary N, repeated initialization, or independently configured
membership. See the [scope audit](revised-20261027/reports/model-audit-and-scope.txt)
and [policy catalog](revised-20261027/models/policy-catalog.json).

Each RPE verifies peer evidence, associates a quote key with authenticated
policy messages, checks the policy hash and peer TCB, excludes its own key,
and rejects duplicate peer keys before computing the full policy join. Policy
and confirmation signatures abstract authentication under the quote-bound
keys; TLS implementation and channel confidentiality are not proved.

The join produces normalized constraints without retaining source-policy
history. A finite-domain specialization of the canonical fold keeps the
protocol queries tractable; separate algebra and specialization regressions
check it against the generic join semantics over the stated domain.

In N=2, Stage 3 checks the quote signature, entity key and fresh challenge,
measurement, signer, product, SVN, TCB status, and attester. The certificate
signature binds the entity key, issuing RPE key, and H(π*). Real SGX/TCB
collateral validation, certificate consumers, and end-to-end TLS are outside
this symbolic model. Availability against the network adversary is not proved.

## Results and interpretation

| Property | Meaning | N=2 | N=3 | N=3 without confirmation |
|---|---|---|---|---|
| Q1 Agreement | Distinct parties that complete hold the same π* | true | true | true |
| Q2 Authenticity | An accepted policy was declared by its owner | true | true | true |
| Q3 Completeness | Local completion follows a full policy join | true | true | true |
| Q4 Issuance | Issuance follows satisfaction of the quote checks | true | — | — |

Q1–Q3 retain their original query shapes. Q4 retains its correspondence and
adds the issuer, entity, key, challenge, attributes, policy, and certificate
body to bind the witness to the actual issuance.

Removing only confirmation does **not** produce an Agreement violation in
this model. Separate coordination queries have reconstructed counterexamples:
a party can complete (and in N=2 issue a compliant certificate) before a peer
has performed its full join. The full models exclude those traces. This
diagnostic does not assert that every peer has already emitted `Confirm`,
and it is neither policy disagreement nor noncompliant issuance. See the
[coordination traces](revised-20261027/reports/coordination-counterexamples.txt).

The final evidence comprises 40 model runs with 127 query results plus seven
isolated primary-query timing runs. All seven primary queries and 19 auxiliary
correspondences hold. Twenty-four rejection scenarios check both a reachable
precondition and rejection at the intended stage. Joint reachability witnesses
place both N=2 completions and legitimate issuances, or all three N=3
completions, in the same execution. No final query is inconclusive.

The seven isolated primary queries took 0.21–0.32 seconds for N=2 and
1.55–1.77 seconds for N=3 on the recorded host. These are single observations,
not averages or timings for every query within a combined run.

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
For the complete regression suite, choose new output names (existing results
are never overwritten). The runner uses noninteractive `sudo`; authenticate
before invoking it if required by the host:

```sh
sudo -v
cd revised-20261027
sh run.sh reproduced-main jobs.txt
sh run.sh reproduced-primary-times jobs-primary-single.txt
```

The runner saves source hashes, commands, parse and verification logs, exit
statuses, elapsed times, environment metadata, and DOT/PDF trace graphs.
It mounts sources read-only and only the new result directory as writable.
Docker networking is disabled; the modeled ProVerif network remains public.

Check the published evidence and its source/log correspondence:

```sh
sha256sum -c SHA256SUMS.public.txt
python3 collect_results.py
```

The collector reads the saved `final-v2` and `primary-single` batches; it does
not run ProVerif or automatically switch to a new run. Deterministic source
generation is available with `python3 generate_models.py`. If changing a
model, preserve prior evidence and collect new results explicitly. Do not
weaken checks or queries solely to obtain successful results.

## Evidence and history

* [Summary](revised-20261027/SUMMARY.txt) and
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

The public artifact excludes manuscript/task attachments, the local delivery
ZIP, duplicate historical logs, and the superseded `final-v1` batch. These
remain in the local full bundle; the public manifest covers the published
revision directory only.
