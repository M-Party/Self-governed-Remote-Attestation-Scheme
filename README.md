# Demo Guide

## Preparation
Assume there are several relying parties. In every party, the **fabric_client**, **RPO**, **RPE** and **CE** should be deployed. But the **fabric_network** could only deployed in one machine where all the relying parties can access it.

### Get the collaterals for Remote Attestion
The following steps should be executed respectively in machines deploying **RPE** and **CE**. In other words, the collaterals of RPE and CE is different if they are not deployed in the same machine.

- Download DCAP in SGX enabled machine in which RPE and CE will be deployed
```
$ cd ~
$ git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git
$ cd SGXDataCenterAttestationPrimitives/SampleCode/QuoteGenerationSample
$ ./app
$ SGX_AESM_ADDR=1 ./app

# Generate quote and test in-process and out-of-process mode. If succeed, it will display text like:

set the enclave load policy as persistent:succeed!
… clean up the enclave load policy:succeed!
```

- Get collaterals
```
$ cd RPO/tool-collateral/
$ make
$ cp
~/SGXDataCenterAttestationPrimitives/SampleCode/QuoteGenerationSample/
quote.dat .  # Copy quote to this dir
$ ./app      # Get collateral from pccs, and before this, make sure the PSW and PCCS is installed successfully. It will display the hash of collaterals and output the collateral.dat file in this dir. Please record the hash and it will be used in the next steps.
```

### Get QEID for Remote Attestation
The following steps should be execute respectively in machines deploying **RPE** and **CE**. In other words, the QEID of RPE and CE is different if they are not deployed in the same machine.

- Install PCKIDRetrievalTool
```
$ echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee
$ /etc/apt/sources.list.d/intel-sgx.list > /dev/null
$ wget -O - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key |
 sudo apt-key add -
$ sudo apt-get update
$ sudo apt-get install sgx-pck-id-retrieval-tool
```

- Modify /opt/intel/sgx-pck-id-retrieval-tool/network_setting.conf:
```
USE_SECURE_CERT=FALSE
user_token = pccs1234  # config "user_token" as pccs's user password，such as pccs1234
proxy_type = xxx       # direct/default/manual
proxy_url = xxx        # if proxy_type is manual, here is the proxy to set
```

- Connect to PCCS
```
$ sudo PCKIDRetrievalTool   # If succeed, it will display the text like:

Intel(R) Software Guard Extensions PCK Cert ID Retrieval Tool Version
1.10.103.1Registration status has been set to completed status.
the data has been sent to cache server successfully and pckid_retrieval.csv has
been generated successfully!
```

- Read the QEID value
```
$ vim pckid_retrieval.csv  # Read and save the fifth value which is the QEID
```

### Build and config fabric network
Fabric network could only deployed in one machine where all the relying parties can access it.

- Build fabric network
```
$ cd fabric_service/fabric_network
$ ./prerequisites.sh
$ sudo ./fabric-network.sh build
```
- Config fabric network
```
# Modify /etc/environment to add fabric peers
$ sudo vim /etc/environment   # Add the following text, and save file

no_proxy=localhost,127.0.0.1,orderer.example.com,peer0.org1.example.com,peer1.org1.example.com,peer0.org2.example.com,peer1.org2.example.com

$ source /etc/environment
```
- Copy and save the **crypto-config** dir in **fabric_service/fabric_network/fixtures/network/** for fabric client to connect to the network, and where to place the dir will be given in the following guide.

### Build and config fabric client
Fabric client should be deployed in every relying party

- Build fabric client
```
$ cd fabric_service/fabric_client
$ ./startup.sh build
```
- Config fabric client
```
$ vim config/config.toml  # "port" is the grpc server port for RPE to connect, whose default value is 50051, and you can modify it on demand. "fabric_network_file" is the path of configuration file called "network.json" for fabric client to connect to fabric network. "channel_name" is the fabric network's blockchain channel name.

$ sed -i 's/0.0.0.0/ip-of-fabric-network/g' config/network.json  # Modify the IP address in network.json file to the IP address of machine deploying fabric network. Replace the "ip-of-fabric-network" in the command to the IP address of machine deploying fabric network.
```

- Add the **crypto-config** dir copied from fabric_network to **fabric_service/fabric_client/fabric_client/** so that fabric client can successfully connect to fabric network

## Formal Verification (ProVerif)

Symbolic models of SRAS mutual attestation and consensus-policy negotiation
live under `formal_verification/`:

- `sras-n2.pv` — N=2 Stage 2 + light Stage 3 (agreement, authenticity, join, issuance)
- `sras-n3.pv` — N=3 full views with H(π*) confirmation
- `sras-n3-ablation.pv` — asymmetric views without confirmation (expected agreement failure)

Build the `sras-proverif` image, mount the directory read-only, then run
`proverif -parse-only` and `proverif` on each model. Full steps, threat model,
query meanings, and reference results are documented in
[`formal_verification/README.md`](formal_verification/README.md).

## SRAS Stage 1 / 2 / 3 Performance Tests

End-to-end latency experiments for the three SRAS stages. All commands assume
the repository root (where `RPE/`, `performance/` live). Outputs go under
`performance_data/` (gitignored).

| Stage | What it measures | Primary harness |
|------:|---|---|
| **1** | RPE init / local setup before multi-party exchange | `performance/performance_test.py --test phase1` |
| **2** | Quote exchange, policy join, H(π*) agreement (P2P or Fabric) | same script (Phase 2 fields in the report); batch: `run_init_n1_10.sh` / `run_init_fabric_n1_10.sh` |
| **3** | CE attestation / certificate issuance wall-clock | `performance/phase3_performance_test.py` |

Related paper-style questions (FT overhead / recovery) remain under
[performance/README.md](performance/README.md) (Q1 / Q2).

### Prerequisites

1. Build templates once: `RPE`, `RPO`, `CE` (`./startup.sh build` in each).
2. Collaterals / QEID configured as in the Demo Guide above.
3. Prefer **P2P** on loopback for Stage 1–2 sweeps (no Fabric). Use Fabric only
   when measuring ledger overhead (`--transport fabric` / `run_init_fabric_n1_10.sh`).
4. After RPE/RPO code changes: rebuild, then
   `rm -rf RPE_party* RPO_party* fabric_client_party*` before setup
   (setup does not refresh enclave binaries inside existing party dirs).

### Stage 1 + 2 (multi-party init)

**One-shot for a single N (P2P):**

```bash
rm -rf RPE_party* RPO_party* fabric_client_party*
python3 performance/setup_multi_party.py --num-parties 4 --transport p2p --p2p-port 51051
python3 performance/start_multi_p2p.py --num-parties 4 --base-port 51051 &
sleep 3
python3 performance/performance_test.py \
  --test phase1 --single 4 \
  --perf-dir performance_data/stage12_p2p_n4
```

`performance_test.py --test phase1` runs the full init path used in Stage 1–2
experiments and writes `test_result_<N>rpes.json` (Phase 1, pre-Phase2 barrier,
Phase 2, remote-quote wait, `t_exchange`, `t_hpi_agree`, totals, etc.).

**Batch N=1..10 (P2P, consensus path, no FT):**

```bash
bash performance/run_init_n1_10.sh performance_data/init_consensus_n1_10 1 10
# sparse list example: bash performance/run_init_n1_10.sh performance_data/out 2 2
# then again for 4, 6, 8 or wrap with a small loop
```

**Batch over Fabric:**

```bash
# requires a working fabric_network deploy
bash performance/run_init_fabric_n1_10.sh performance_data/init_fabric_n1_10 1 10
```

**Summarize existing JSON files:**

```bash
python3 performance/performance_test.py \
  --perf-dir performance_data/init_consensus_n1_10 \
  --report-from 2 4 6 8
```

### Injected network delay (NetEm)

`performance/run_with_netem_delay.py` applies Linux `tc netem` on a device
(default `lo`). `--delay-ms` is the **target RTT**; one-way delay is RTT/2
(both directions share the qdisc on loopback).

```bash
# Smoke-check ~20 ms RTT
python3 performance/run_with_netem_delay.py --delay-ms 20 -- \
  python3 performance/verify_netem_delay.py --count 3

# Stage 1–2 under 20 ms / 50 ms RTT (example: sparse N)
python3 performance/run_with_netem_delay.py --delay-ms 20 --dev lo -- \
  bash performance/run_init_n1_10.sh performance_data/p2p_delay20 2 2

python3 performance/run_with_netem_delay.py --delay-ms 50 --dev lo -- \
  bash performance/run_init_n1_10.sh performance_data/p2p_delay50 2 2
```

Always clear leftover qdisc if a run is interrupted:

```bash
sudo tc qdisc del dev lo root 2>/dev/null || true
```

### Stage 3 (CE authentication)

Wait until **all RPEs finished Phase 2** and entered Stage 3 before starting CEs.

```bash
# Example: 1 issuing RPE already up from Stage 1–2, or start a fresh 1-party stack
python3 performance/setup_multi_party.py --num-parties 1 --transport p2p
python3 performance/setup_multi_ce.py --num-ces 4 --rpe-address 127.0.0.1 --rpe-port 4455
python3 performance/start_multi_p2p.py --num-parties 1 --base-port 51051 &
python3 performance/start_multi_rpo.py --num-parties 1 &
python3 performance/start_multi_rpe.py --num-parties 1
# wait for "Phase two finished" / phase three ready in RPE logs
```

**CE-first + total-time** (aligned start via `CE_WAIT_FOR_START_RPE=1` /
`START_RPE_NOW.flag`; reports CE-side and RPE-side wall-clock from first
`auth_start` to last `auth_end`):

```bash
python3 performance/phase3_performance_test.py \
  --single 4 --ce-first --total-time \
  --perf-dir performance_data/stage3_ce4_cefirst_total \
  --rpe-dir RPE_party1
```

**Repeat N authentications** (collector first, then start CEs) — also used for
FT Q1 overhead; see [performance/README.md](performance/README.md):

```bash
python3 performance/phase3_performance_test.py \
  --repeat 5 \
  --perf-dir performance_data/stage3_repeat5 \
  --rpe-dir RPE_party1
# other terminal:
python3 performance/start_multi_ce.py --num-parties 1
```

Stage 3 under NetEm (same RTT convention):

```bash
python3 performance/run_with_netem_delay.py --delay-ms 20 -- \
  python3 performance/phase3_performance_test.py \
    --single 4 --ce-first --total-time \
    --perf-dir performance_data/stage3_delay20_ce4 \
    --rpe-dir RPE_party1
```

### Cleanup between runs

```bash
python3 performance/start_multi_p2p.py --num-parties 10 --base-port 51051 --stop
python3 performance/start_multi_rpe.py --num-parties 10 --stop
python3 performance/start_multi_rpo.py --num-parties 10 --stop
for p in $(seq 4433 4442) $(seq 4455 4464) $(seq 51051 51060); do
  fuser -k -9 "${p}/tcp" 2>/dev/null || true
done
rm -rf RPE_party* RPO_party* fabric_client_party* CE_party*
sudo tc qdisc del dev lo root 2>/dev/null || true
```

## Performance Experiments

### Phase 2 ledger-overhead ablation: SRAS-Fabric vs SRAS-P2P

SRAS uses Hyperledger Fabric by default in Phase 2 to exchange RPE Quotes among participants. To separate the protocol overhead from the exchange substrate overhead, this repository also provides a degraded experimental substrate:

- `performance/p2p_quote_exchange.py`
  - An in-memory Quote exchange service compatible with the existing gRPC interface, without relying on the Fabric ledger.
- `performance/start_multi_p2p.py`
  - Starts and stops the P2P service above.
- `performance/phase2_transport_ablation_test.py`
  - Compares the latency of the `Fabric` and `P2P` exchange substrates under the same Phase 2 workflow.

Experiment goals:

- Compare the Phase 2 latency of `SRAS-Fabric` and `SRAS-P2P` with `N` participants.
- Quantify the mutual-attestation latency added by introducing Fabric.
- Observe the core protocol overhead separately from the ledger/exchange-substrate overhead.

Example:

```bash
python3 performance/phase2_transport_ablation_test.py --party-counts 2,4,8 --repeats 3
```

Output files:

- `performance_data/phase2_transport_ablation/summary.csv`
- `performance_data/phase2_transport_ablation/summary_aggregated.csv`
- `performance_data/phase2_transport_ablation/summary.json`

Metrics:

- `phase2_wall_clock_s` is the system-level Phase 2 wall-clock time: `max(phase2_end) - min(phase2_start)`.
- `phase2_avg_s` / `phase2_min_s` / `phase2_max_s` are Phase 2 latency statistics recorded locally by each RPE.


### Q1: SRAS-FT attestation overhead (state propagation + echo verification)

**Question:** What is the attestation overhead introduced by SRAS-FT before TEE certificate issuance?

Compare **baseline SRAS** (`ft.enabled = false`) vs **SRAS-FT** (`ft.enabled = true`) under the same multi-party deployment. Measure how much total authentication latency increases after adding state propagation and echo verification.

Quick start (5-party P2P, FT enabled):

```bash
# 1. Setup (add --ft-enabled for SRAS-FT; omit for baseline)
python3 performance/setup_multi_party.py --num-parties 5 --transport p2p --p2p-port 51051 --ft-enabled
python3 performance/setup_multi_ce.py --num-ces 3 --rpe-address 127.0.0.1 --rpe-port 4455

# 2. Start (wait until all RPEs finish Phase 2)
python3 performance/start_multi_p2p.py --num-parties 5 --base-port 51051
python3 performance/start_multi_rpo.py --num-parties 5
python3 performance/start_multi_rpe.py --num-parties 5

# 3. Collect N new CE authentications from issuing RPE (start before CE)
python3 performance/phase3_performance_test.py --repeat 5 \
  --perf-dir performance_data/q1_ft_n5 --rpe-dir RPE_party1

# 4. Trigger CE attestation
python3 performance/start_multi_ce.py --num-parties 3
```

Output: `performance_data/q1_ft_n5/state_update_report.{txt,csv,xlsx,json}`

Key metrics: `auth_total`, `quote_verify`, `rpc(incl.remote.veri+record)`, `remote.veri+record`, `verify_echo`.

See [performance/README.md](performance/README.md) for the full step-by-step guide (Chinese), timing semantics, baseline comparison, and troubleshooting.

### Q2: SRAS-FT failed RPE recovery latency

Measure recovery time after crash/restart (RecoveryQuery → verify quotes/states → max counter → broadcast new quote):

```bash
python3 performance/q2_ft_recovery_test.py --repeat 3 \
  --rpe-dir RPE_party1 --perf-dir performance_data/q2_n5 --label n5
# then per repeat: kill RPE, cd RPE_party1 && ./startup.sh start
```

See [performance/README.md](performance/README.md) for Q2 details. Do not use `start_multi_rpe.py --stop` for crash simulation (it deletes expt_cache).

### Build and config Relying Party Owner (RPO)
RPO should be deployed in every relying party

- Build RPO
```
$ cd RPO/
$ ./startup.sh build
```

- Config RPO
```
# Generate the ecdsa-384 keys for RPO to endorese RPE.
$ openssl ecparam -genkey -name secp384r1 -out private-signing-key.pem
$ openssl ec -in private-signing-key.pem -pubout -out public-signing-key.pem

$ vim config.toml  # "rpe_id", the id of RPE which will connect to the RPO, can be modified on demand; "policies_path" is the path of policies.json file; "private_key_path" is the path of private-signing-key.pem file, which is the private key of RPO; "port" is this RPO's RA-TLS server port for RPE to connect, whose default value is 4433, and you can modify it on demand.

$ mkdir collaterals  # Here to place RPE's collateral, only the collateral of RPE which will be verified by this RPO
$ cd collaterals  # Copy RPE's collateral to this dir, and rename it starting with "tcb-" and ending up with ".dat" such as "tcb-1.dat" 
```

### Build and config Relying Party Enclave (RPE)
RPE should be deployed in every relying parties and it should be build once and every relying parties use the same RPE software and measurements.

- Build RPE
```
$ cd RPE/
$ ./startup.sh build   # Record the measurements(mrenclave, mrsigner, isv_prod_id, isv_svn) displayed after finishing building for the next steps
```

- Config RPE
```
$ vim config.toml  # "rpe_id", the id of RPE which will connect to the RPO, can be modified on demand but should match the id in RPO's config.toml file; "grpc_address" is the IP address and grpc port of fabric_client for RPE to connect, and you can modify the port on demand but should match the value in fabric_client's config.toml; "rpo_address" is the IP address of RPO for this RPE to connect; "rpo_port" is the RA-TLS port of RPO which this RPE can use to connect to RPO, whose default value is 4433, and you can modify it on demand but should match the value in RPO's config.toml; "rpe_port" is this RPE's RA-TLS server port for CE to connect, whose default value is 4455, and you can modify it on demand.

$ mkdir collaterals  # Here to place RPEs' and CEs' collateral, including RPEs in all relying parties and the CEs will be verified by this RPE
$ cd collaterals  # Copy  RPEs's and CEs' collaterals to this dir, and rename them starting with "tcb-" and ending up with ".dat" such as "tcb-2.dat" 
```

### Build and config Customer Enclave (CE)
Every relying party should deploy at least one CE

- Build CE in a cmd in Intranet
```
$ cd CE/
$ ./startup.sh build   # Record the measurements(mrenclave, mrsigner, isv_prod_id, isv_svn) displayed after finishing building for the next steps.
```

- Config CE
```
$ vim config.toml  # "local_ce", the id of CE which will connect to the RPE, can be modified on demand; "rpe_address" is the IP address of RPE for this CE to connect; "rpe_port" is the RA-TLS server port of RPE which this CE can use to connect to RPE, whose default value is 4455, and you can modify it on demand but should match the value in RPE's config.toml
```

### Edit policies in RPO
Set the policies to make sure all the relying parties reach consensus.
```
$ cd RPO/
$ vim policies.json
# Edit policies.json
-session_id: the only value for this project, a base64 encoded value;
-rpe_info: RPE's measurements, modify them to the values when building RPE;
-tcb: the collateral list used of all relying parties to do attestation for SGX, in which "id" is the name of collateral starting with "tcb-" and ending up with ".dat", "data" is the hash of collateral;
-rpe: list RPEs info in all relying parties, "id" is RPE's identity such as "rpe-1",
"qeid_allowed" is the QEID of machine deploying RPE, "tcb_allowed" is the collateral allowed list and the value set in this list should match the "id" value in tcb, and "ca_signing_key_cert" is RPO's public signing key, use the content of public-signing-key.pem to fill in it;
-ce: the info of CEs in all relying parties, in which the "id" is CE's identity such as "ce-1", and the others are CE's measurements;
-job: a list indicate one party can run which RPE and CE, for example, party-1 runs rpe-1 to verify ce-1, in which the "id" is job's idendity like "job-1", the "rpe" is RPE's id, the "ce" is CE's id, the "cust_qeid_allowed" is the QEID of machine deploying CE, and the "tcb_allowed" is the collateral allowed list and the value set in this list should match the "id" value in tcb;
-connection: a list indicate the communication relationship of two jobs, for example, ce-1 is a server waiting for client ce-2 to connect.
```

The following is a sample.
```
{
    "session_id": "Session-1",
    "description": "This is an example for policies description.",
    "rpe_info":{
        "mrenclave": "741875db0d85f663a7a31cea6aba088b17525b63c271139f7d47b82b8c949148",
        "mrsigner": "a08080020e2dd98e41cae63d7411609a7efcd7470123aaaeed664a7caac72cea",
        "isv_prod_id": "0",
        "isv_svn": "0"
    },

    "tcb": [
        {
            "id": "tcb-1",
            "fmspc": "fmspc-1",
            "data": "2TYpq641ZRVlMUcL5zmicXwcck/6HXn2Oq+UuuEEu3/a/BdhRxxg5Yz5t6CK2baB"
        },
        {
            "id": "tcb-2",
            "fmspc": "fmspc-2",
            "data": "2TYpq641ZRVlMUcL5zmicXwcck/6HXn2Oq+UuuEEu3/a/BdhRxxg5Yz5t6CK2baB"
        }
    ],
    "rpe": [
        {
            "id": "rpe-1",
            "qeid_allowed": ["efbac5bb8d8cd796a8379405e5e846e2"],
            "tcb_allowed": ["tcb-1"] ,     
            "ca_signing_key_cert": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEk6FRWht1RYYKye3sEkm935yg194BBJou\ndiudwMAZlmz5tFNSWKmYMfutRn5+nesXP67g/VUlH1PvEZl092im0LKZxfRMLCxz\nn1gx1niUEjZnocRsCsxyhnWWwV5MAPMc\n-----END PUBLIC KEY-----"
        },
        {
            "id": "rpe-2",
            "qeid_allowed": ["efbac5bb8d8cd796a8379405e5e846e2"],
            "tcb_allowed": ["tcb-2"],
            "ca_signing_key_cert": "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBPB1WB9tbtVjRozV3VfUSweV8fyhWzGw\nJ28N7KWoNQckBg3VbHbuNVQgZz5w/hdnNG7neGD+tfQmWCgdV+eB/duxox6QAxrK\nxiMEnaw3K+4SUKx+m6pmplqchCgsdlEA\n-----END PUBLIC KEY-----"
        }
    ], 
    "ce": [
        {
            "id": "ce-1",
            "mrenclave": "48a9d2caa0722c978aa3432481be9c04f3dc6a90b739a5e08ee8f08eb05ac0ce",
            "mrsigner": "a08080020e2dd98e41cae63d7411609a7efcd7470123aaaeed664a7caac72cea",
            "isv_prod_id": "0",
            "isv_svn": "0"
        }
    ],
    "job": [
        {
            "id": "job-1",
            "rpe": "rpe-1",
            "ce": "ce-1",
            "cust_qeid_allowed": ["efbac5bb8d8cd796a8379405e5e846e2"],
            "tcb_allowed": ["tcb-1"]
        },
        {
            "id": "job-2",
            "rpe": "rpe-2",
            "ce": "ce-1",
            "cust_qeid_allowed": ["efbac5bb8d8cd796a8379405e5e846e2"],
            "tcb_allowed": ["tcb-2"]
        }
    ],
    "connection": [
        {
            "id": "connection-1",
            "server": "job-2",
            "clients": ["job-1"]
        }
    ]
}
```

## Running the Self-governed Remote Attestation Scheme
The following example showcase two relying parties named **party-1** and **party-2** to run the Self-governed Remote Attestation Scheme. 

### Stage one
#### 1. Run fabric network
```
$ cd fabric_service/fabric_network/
$ sudo ./fabric-network.sh start
```

#### 2. Run party-1's fabric client, RPO and RPE

- Run party-1's fabric client
```
$ cd fabric_service/fabric_client/
$ sudo ./startup.sh start
```

- Run party-1's RPO
```
$ cd RPO/
$ ./startup.sh start
```

- Run party-1's RPE
```
$ cd RPE/
$ ./startup.sh start
```

#### 3. Run party-2's fabric client, RPO and RPE

- Run party-2's fabric client
```
$ cd fabric_service/fabric_client/
$ sudo ./startup.sh start
```

- Run party-2's RPO
```
$ cd RPO/
$ ./startup.sh start
```

- Run party-2's RPE
```
$ cd RPE/
$ ./startup.sh start
```

### Stage two
When RPEs successfully running, the two RPE will do attestation and verification for each other.

### Stage three
#### 4. Run CE

- Run party-1's CE
```
$ cd CE/
$ ./startup.sh start
```

- Run party-2's CE
```
$ cd CE/
$ ./startup.sh start
```

### Stage four
After two CEs successfully running and verified by the RPEs, RPEs will get counter part's public keys of CEs. Rpe-1 will send ce-2's public key to ce-1, and rpe-2 will send ce-1's public key to ce-2.

## Shutdown guide

- For fabric network
```
$ sudo ./fabric_network.sh stop
```

- For fabric client
```
$ sudo ./startup.sh stop
```

- For RPO
```
$ ./startup.sh stop
```

- For RPE
```
$ ./startup.sh stop
```

- For CE
```
$ ./startup.sh stop
```
