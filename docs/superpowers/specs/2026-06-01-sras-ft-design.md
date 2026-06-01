# SRAS-FT Design

## Goal

SRAS-FT extends the existing SRAS flow with fault-tolerant attestation state
synchronization and recovery. The baseline SRAS behavior remains unchanged by
default. FT logic is enabled only when `ft.enabled = true` is configured for an
RPE.

The implementation must be minimally invasive:

- Keep the existing Phase 2 Fabric/P2P Quote exchange unchanged.
- Insert FT state propagation only before Phase 3 CE certificate issuance.
- Add recovery as an RPE startup path when a local Expt cache exists.
- Avoid rewriting the RA-TLS, policy, certificate, or transport subsystems.

## Non-Goals

- Do not replace the existing Fabric/P2P Phase 2 exchange.
- Do not use the existing external P2P node as the FT quorum mechanism.
- Do not expose RPE signing keys to external P2P nodes.
- Do not require FT for baseline experiments.

## Architecture

Each RPE owns a small FT control service running inside the RPE process. This
service exposes direct peer RPC endpoints for:

- `state_update`: record another RPE's CE attestation state and return a signed
  Echo.
- `recovery_query`: return the responder's Evidence Quote and the latest state
  recorded for the recovering RPE.
- `evidence_update`: accept and verify a recovering RPE's fresh Evidence Quote
  and update its public key.

The FT control service is separate from the existing Phase 2 exchange service.
The existing Fabric/P2P transport remains responsible only for RPE Evidence Quote
exchange during mutual attestation.

## Configuration

Add an optional `[ft]` section to `RPE/config.toml.template` and generated RPE
configs:

```toml
[ft]
enabled = false
f = 1
listen_host = "127.0.0.1"
listen_port = "56001"
peer_addresses = "rpe-1=127.0.0.1:56001,rpe-2=127.0.0.1:56002"
echo_timeout_sec = 3
recovery_timeout_sec = 5
state_store_path = "performance_data/ft_state.json"
expt_cache_path = "performance_data/expt_cache.json"
```

`enabled = false` preserves baseline SRAS.

`peer_addresses` maps RPE IDs to FT control endpoints. The local RPE may appear
in the map, but send paths skip the local ID.

## Data Model

Attestation state:

```json
{
  "target_rpe_id": "rpe-1",
  "tee_id": "ce-1",
  "attestation_counter": 3,
  "nonce": "base64-random",
  "timestamp": 1710000000.123
}
```

Signed state update:

```json
{
  "state": {},
  "sender_rpe_id": "rpe-1",
  "signature": "base64-ecdsa-signature"
}
```

Signed Echo:

```json
{
  "responder_rpe_id": "rpe-2",
  "target_rpe_id": "rpe-1",
  "tee_id": "ce-1",
  "attestation_counter": 3,
  "nonce": "base64-random",
  "signature": "base64-ecdsa-signature"
}
```

Recovery response:

```json
{
  "responder_rpe_id": "rpe-2",
  "evidence_quote": "base64-json-evidence-quote",
  "rpe_public_key": "pem",
  "expt_hash": "base64-sha384",
  "recorded_attestation_state": {},
  "signed_state": {},
  "recovery_nonce": "base64-random"
}
```

Canonical JSON with sorted keys is used for signing and verification to avoid
signature mismatches caused by key ordering.

## Phase 3 State Propagation

The existing Phase 3 `REQ_CERT` flow currently performs:

```text
perform_handshake()
verify_peer()
receive REQ_CERT
get_ce_info()
verify_ce_body()
generate_ce_certificate()
send_ce_cert()
```

With FT enabled, insert state propagation after `verify_ce_body()` succeeds and
before certificate generation:

```text
perform_handshake()
verify_peer()
receive REQ_CERT
get_ce_info()
verify_ce_body()
allocate or increment AC_j for tee_id
build AttestationState(target_rpe_id, tee_id, AC_j, nonce)
sign state with local RPE signing key
send state_update RPC to peer RPE FT services in parallel
validate signed Echo responses
continue only if valid Echo count >= f + 1
generate_ce_certificate()
send_ce_cert()
```

If the FT quorum is not reached before `echo_timeout_sec`, certificate issuance
is aborted for that CE connection.

The local RPE persists its local attestation counter and remote recorded states
to `state_store_path`.

## State Update Handler

When an online RPE receives a state update:

1. Parse the signed state update.
2. Verify the sender RPE ID exists in the verified Phase 2 `self.rpes` map.
3. Verify the update signature with the sender's verified RPE public signing key.
4. Reject missing or malformed nonce values.
5. Compare the incoming counter with the locally recorded counter for
   `recorded_remote_state[target_rpe_id][tee_id]`.
6. Store the update only if the incoming counter is newer.
7. Sign and return a Signed Echo using the local RPE signing key.

Replay protection for state updates is nonce-based. Each processed nonce is
remembered with a bounded in-memory cache and persisted state is updated only for
newer counters.

## Recovery Flow

At RPE startup:

1. If no local Expt cache exists, run the normal RPO authorization path.
2. After successful RPO authorization, persist the Expt/policies cache locally.
3. If the Expt cache exists and FT is enabled, run recovery before accepting CE
   authentications.

Recovering RPE recovery steps:

1. Generate a fresh `recovery_nonce`.
2. Send `recovery_query(recovering_rpe_id, recovery_nonce)` to peer FT services.
3. Wait for at least `f + 1` valid responses before `recovery_timeout_sec`.
4. For each response, verify:
   - The nonce matches the requested recovery nonce.
   - The Evidence Quote is valid under the locally cached Expt and collateral.
   - The Evidence Quote binds the returned RPE public key.
   - The returned Expt hash matches the local Expt hash.
   - The signed state verifies with the public key bound in the Evidence Quote.
5. Select the largest attestation counter across valid responses.
6. Restore the local attestation counter to that maximum.
7. Regenerate the local RPE signing key pair.
8. Generate a fresh Evidence Quote binding the new public key and Expt hash.
9. Broadcast `evidence_update` to online RPEs so they update the recovering RPE's
   public key.

If recovery quorum is not reached, the RPE logs the failure and does not enter
Phase 3 serving mode.

## Online Recovery Query Handler

When an online RPE receives a recovery query:

1. Verify the request contains a valid `recovering_rpe_id` and nonce.
2. Generate or refresh an Evidence Quote that binds:
   - responder public signing key
   - local Expt hash
   - recovery nonce
3. Look up the latest state recorded for the recovering RPE.
4. Return the Evidence Quote, public key, Expt hash, recorded state, signed state,
   and nonce.

If no recorded state exists for the recovering RPE, the handler returns an empty
state with a nonzero status and logs the event.

## Replay Protection

State propagation:

- `AttestationState` includes a fresh nonce.
- Signed Echo includes the same nonce.
- The target RPE accepts only Echoes matching the current nonce.
- Receivers reject repeated processed nonces.

Recovery:

- Recovering RPE sends a fresh recovery nonce.
- Each response must include the same nonce.
- Duplicate responder IDs for the same nonce are ignored.
- Responses with missing, mismatched, or replayed nonce values are rejected.

## Persistence

FT state is persisted as JSON under `state_store_path`:

```json
{
  "local_attestation_counters": {
    "ce-1": 3
  },
  "recorded_remote_state": {
    "rpe-1": {
      "ce-1": {
        "target_rpe_id": "rpe-1",
        "tee_id": "ce-1",
        "attestation_counter": 3,
        "nonce": "base64-random",
        "signature": "base64-ecdsa-signature",
        "sender_rpe_id": "rpe-1"
      }
    }
  }
}
```

Writes use a temporary file and atomic rename, matching the existing performance
data persistence style.

## Testing

Unit-level checks:

- Canonical signing and verification for state updates.
- Echo signature verification.
- Replay rejection for repeated nonces.
- Counter merge chooses the maximum valid counter.

Integration checks:

- Baseline SRAS with `ft.enabled = false` follows the existing certificate
  issuance path.
- FT enabled with enough online peers signs a CE certificate only after receiving
  `f + 1` valid Echoes.
- FT enabled with insufficient Echoes aborts certificate issuance.
- Recovery collects valid responses, verifies responder Evidence Quotes, restores
  the maximum attestation counter, and broadcasts a fresh Evidence Quote.

## Implementation Boundaries

Expected touched areas:

- `RPE/relying_party_enclave/rpe.py`: FT startup, Phase 3 insertion point,
  recovery entry point.
- New `RPE/relying_party_enclave/ft_control.py`: FT service, client calls,
  signing helpers, persistence.
- `RPE/config.toml.template`: optional FT config.
- `performance/setup_multi_party.py`: generate per-party FT ports and peer maps
  when requested.

Generated protobuf files are avoided initially by using a lightweight HTTP JSON
or TCP JSON control service. If gRPC is later required, proto generation becomes
a separate mechanical step.
