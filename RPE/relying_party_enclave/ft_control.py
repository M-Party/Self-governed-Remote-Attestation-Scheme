import base64
import binascii
import json
import logging
import os
import secrets
import threading
import time
from concurrent import futures
from dataclasses import dataclass

import grpc
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

FT_GRPC_SERVICE = "srasft.FTControl"


def b64encode_bytes(data):
    return base64.b64encode(data).decode("ascii")


def b64decode_text(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, UnicodeError) as exc:
        raise ValueError("invalid base64 data") from exc


def canonical_json_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_json(private_key, payload):
    signature = private_key.sign(canonical_json_bytes(payload), ec.ECDSA(hashes.SHA384()))
    return b64encode_bytes(signature)


def verify_json_signature(public_key, payload, signature_b64):
    try:
        signature = b64decode_text(signature_b64)
        public_key.verify(signature, canonical_json_bytes(payload), ec.ECDSA(hashes.SHA384()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def elapsed_ms(start):
    return (time.perf_counter() - start) * 1000.0


def load_public_key_pem(public_key_pem):
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    return serialization.load_pem_public_key(public_key_pem, backend=openssl_backend)


class FTGrpcCancelledError(Exception):
    """Raised when an FT gRPC call is cancelled before completion."""


class GrpcPeerChannelPool:
    def __init__(self):
        self._lock = threading.Lock()
        self._channels = {}
        self._stubs = {}

    def _channel_locked(self, address):
        channel = self._channels.get(address)
        if channel is None:
            channel = grpc.insecure_channel(address)
            self._channels[address] = channel
        return channel

    def _stub_locked(self, address, method):
        key = (address, method)
        rpc = self._stubs.get(key)
        if rpc is None:
            channel = self._channel_locked(address)
            rpc = channel.unary_unary(
                "/%s/%s" % (FT_GRPC_SERVICE, method),
                request_serializer=lambda value: value,
                response_deserializer=lambda value: value,
            )
            self._stubs[key] = rpc
        return rpc

    def _evict_locked(self, address):
        channel = self._channels.pop(address, None)
        for key in [item for item in self._stubs if item[0] == address]:
            self._stubs.pop(key, None)
        return channel

    def evict(self, address):
        with self._lock:
            channel = self._evict_locked(address)
        if channel is not None:
            channel.close()

    def post_json(self, address, method, payload, timeout, cancel_event=None):
        if cancel_event is not None and cancel_event.is_set():
            raise FTGrpcCancelledError("FT gRPC call cancelled before send")
        with self._lock:
            rpc = self._stub_locked(address, method)
        try:
            response_bytes = rpc(
                canonical_json_bytes(payload),
                timeout=timeout,
                wait_for_ready=True,
            )
        except Exception:
            self.evict(address)
            raise
        if cancel_event is not None and cancel_event.is_set():
            raise FTGrpcCancelledError("FT gRPC call cancelled after response")
        return json.loads(response_bytes.decode("utf-8"))

    def close(self):
        with self._lock:
            channels = list(self._channels.values())
            self._channels.clear()
            self._stubs.clear()
        for channel in channels:
            channel.close()


class PublicKeyCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._by_pem = {}

    def _pem_bytes(self, public_key_pem):
        if isinstance(public_key_pem, str):
            return public_key_pem.encode("utf-8")
        return public_key_pem

    def get_or_load(self, public_key_pem):
        pem_bytes = self._pem_bytes(public_key_pem)
        with self._lock:
            cached = self._by_pem.get(pem_bytes)
            if cached is not None:
                return cached
        parsed = load_public_key_pem(pem_bytes)
        with self._lock:
            cached = self._by_pem.get(pem_bytes)
            if cached is not None:
                return cached
            self._by_pem[pem_bytes] = parsed
            return parsed

    def invalidate_pem(self, public_key_pem):
        pem_bytes = self._pem_bytes(public_key_pem)
        with self._lock:
            self._by_pem.pop(pem_bytes, None)


def _quorum_already_met(stop_event, valid_echoes, quorum_target):
    return stop_event.is_set() or len(valid_echoes) >= quorum_target


def derive_ft_quorum(num_rpes, quorum_override=0):
    if num_rpes <= 0:
        raise ValueError("num_rpes must be positive")
    if quorum_override is None:
        quorum_override = 0
    quorum_override = int(quorum_override)
    if quorum_override < 0:
        raise ValueError("quorum_override must be >= 0")
    if quorum_override > 0:
        if quorum_override > num_rpes:
            raise ValueError("quorum_override must be <= num_rpes")
        return quorum_override
    tolerated_faults = (num_rpes - 1) // 2
    return tolerated_faults + 1


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    token = str(value).strip().strip('"').lower()
    if token in ("1", "true", "yes", "on"):
        return True
    if token in ("0", "false", "no", "off"):
        return False
    raise ValueError("boolean config value must be one of 1,true,yes,on,0,false,no,off")


def _as_int(value, default):
    if value is None:
        return default
    return int(str(value).strip().strip('"'))


def _as_str(value, default):
    if value is None:
        return default
    return str(value).strip().strip('"')


def parse_peer_addresses(raw_value):
    if not raw_value:
        return {}
    peers = {}
    for item in str(raw_value).strip().strip('"').split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError("peer address must use rpe_id=host:port format")
        rpe_id, address = item.split("=", 1)
        rpe_id = rpe_id.strip()
        address = address.strip()
        if not rpe_id:
            raise ValueError("peer rpe_id must not be empty")
        if rpe_id in peers:
            raise ValueError("duplicate peer rpe_id")
        if not address or ":" not in address:
            raise ValueError("peer address must use host:port format")
        host, port_text = address.rsplit(":", 1)
        host = host.strip()
        port_text = port_text.strip()
        if not host:
            raise ValueError("peer address host must not be empty")
        if not port_text.isdigit():
            raise ValueError("peer address port must be numeric")
        port = int(port_text)
        if port < 1 or port > 65535:
            raise ValueError("peer address port must be in range 1..65535")
        peers[rpe_id] = f"{host}:{port_text}"
    return peers


@dataclass
class FTConfig:
    enabled: bool
    local_rpe_id: str
    listen_host: str
    listen_port: int
    peer_addresses: dict
    echo_timeout_sec: float
    recovery_timeout_sec: float
    expt_cache_path: str
    counter_cache_path: str
    ft_quorum: int

    @classmethod
    def from_conf(cls, conf, num_rpes, local_rpe_id):
        ft_conf = conf.get("ft", {}) if isinstance(conf, dict) else {}
        quorum_override = _as_int(ft_conf.get("quorum_override"), 0)
        return cls(
            enabled=_as_bool(ft_conf.get("enabled"), False),
            local_rpe_id=local_rpe_id,
            listen_host=_as_str(ft_conf.get("listen_host"), "127.0.0.1"),
            listen_port=_as_int(ft_conf.get("listen_port"), 56000),
            peer_addresses=parse_peer_addresses(ft_conf.get("peer_addresses", "")),
            echo_timeout_sec=float(_as_str(ft_conf.get("echo_timeout_sec"), "3")),
            recovery_timeout_sec=float(_as_str(ft_conf.get("recovery_timeout_sec"), "8")),
            expt_cache_path=_as_str(ft_conf.get("expt_cache_path"), "collaterals/expt_cache.json"),
            counter_cache_path=_as_str(
                ft_conf.get("counter_cache_path"), "collaterals/ft_counter_cache.json"
            ),
            ft_quorum=derive_ft_quorum(num_rpes, quorum_override),
        )


class FTStateStore:
    def __init__(self, counter_cache_path):
        self.counter_cache_path = counter_cache_path
        self.lock = threading.Lock()
        self.local_attestation_counters = {}
        self.recorded_remote_state = {}
        self.seen_nonces = {}
        self._load_counter_cache()

    def _load_counter_cache(self):
        try:
            with open(self.counter_cache_path, "r", encoding="utf-8") as cache_file:
                payload = json.load(cache_file)
        except FileNotFoundError:
            return

        counters = payload.get("local_attestation_counters", {})
        self.local_attestation_counters = {
            str(tee_id): int(counter) for tee_id, counter in counters.items()
        }

    def _save_counter_cache_locked(self):
        directory = os.path.dirname(self.counter_cache_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        temp_path = f"{self.counter_cache_path}.tmp"
        payload = {"local_attestation_counters": self.local_attestation_counters}
        with open(temp_path, "w", encoding="utf-8") as cache_file:
            json.dump(payload, cache_file, sort_keys=True, separators=(",", ":"))
        os.replace(temp_path, self.counter_cache_path)

    def next_local_counter(self, tee_id):
        tee_id = str(tee_id)
        with self.lock:
            counter = int(self.local_attestation_counters.get(tee_id, 0)) + 1
            self.local_attestation_counters[tee_id] = counter
            self._save_counter_cache_locked()
            return counter

    def restore_local_counter_floor(self, tee_id, counter):
        tee_id = str(tee_id)
        counter = int(counter)
        with self.lock:
            current = int(self.local_attestation_counters.get(tee_id, 0))
            self.local_attestation_counters[tee_id] = max(current, counter)
            self._save_counter_cache_locked()

    def mark_nonce_seen(self, nonce):
        if not nonce:
            return False
        nonce = str(nonce)
        with self.lock:
            if nonce in self.seen_nonces:
                return False
            self.seen_nonces[nonce] = None
            if len(self.seen_nonces) > 10000:
                self.seen_nonces = dict(list(self.seen_nonces.items())[-5000:])
            return True

    def record_remote_state(self, state, signed_update):
        try:
            target_rpe_id = str(state["target_rpe_id"])
            tee_id = str(state["tee_id"])
            counter = int(state["attestation_counter"])
        except (KeyError, TypeError, ValueError):
            return False
        if not target_rpe_id or not tee_id:
            return False

        with self.lock:
            target_states = self.recorded_remote_state.setdefault(target_rpe_id, {})
            existing = target_states.get(tee_id)
            if existing is not None and counter <= int(existing["state"]["attestation_counter"]):
                return False

            stored_state = dict(state)
            stored_state["attestation_counter"] = counter
            target_states[tee_id] = {
                "state": stored_state,
                "signed_update": dict(signed_update),
            }
            return True

    def get_recorded_state(self, target_rpe_id):
        with self.lock:
            target_states = self.recorded_remote_state.get(target_rpe_id)
            if not target_states:
                return None
            return max(
                target_states.values(),
                key=lambda entry: int(entry["state"]["attestation_counter"]),
            )

    def zero_attestation_state(self, target_rpe_id):
        return {
            "target_rpe_id": str(target_rpe_id),
            "tee_id": "",
            "attestation_counter": 0,
        }


def random_nonce():
    return b64encode_bytes(secrets.token_bytes(32))


class FTControlManager:
    def __init__(
        self,
        config,
        signing_private_key,
        signing_public_key_pem,
        peer_public_keys,
        quote_verifier=None,
        on_peer_key_update=None,
        nonce_factory=None,
    ):
        self.config = config
        self.signing_private_key = signing_private_key
        self.signing_public_key_pem = signing_public_key_pem
        self.peer_public_keys = dict(peer_public_keys)
        self.quote_verifier = quote_verifier
        self.on_peer_key_update = on_peer_key_update
        self.nonce_factory = nonce_factory or random_nonce
        self.state_store = FTStateStore(config.counter_cache_path)
        self.last_propagation_timings = {}
        self.last_recovery_timings = {}
        self._public_key_cache = PublicKeyCache()
        self._grpc_pool = GrpcPeerChannelPool()
        self._server = None
        self._bound_address = None
        self._pending_evidence_updates = {}
        self._pending_evidence_updates_lock = threading.Lock()

    def start(self):
        if not self.config.enabled:
            return
        manager = self

        def make_handler(fn):
            def handler(request_bytes, _context):
                try:
                    payload = json.loads(request_bytes.decode("utf-8"))
                    response = fn(payload)
                except Exception as exc:
                    logger.exception("FT gRPC request failed")
                    response = {"status": 1, "error": str(exc)}
                return canonical_json_bytes(response)

            return grpc.unary_unary_rpc_method_handler(
                handler,
                request_deserializer=lambda value: value,
                response_serializer=lambda value: value,
            )

        generic_handler = grpc.method_handlers_generic_handler(
            FT_GRPC_SERVICE,
            {
                "StateUpdate": make_handler(manager.handle_state_update),
                "RecoveryQuery": make_handler(manager.handle_recovery_query),
                "EvidenceUpdate": make_handler(manager.handle_evidence_update),
                "Ping": make_handler(manager.handle_ping),
            },
        )
        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
        self._server.add_generic_rpc_handlers((generic_handler,))
        bind_address = "%s:%d" % (self.config.listen_host, self.config.listen_port)
        bound_port = self._server.add_insecure_port(bind_address)
        if bound_port == 0:
            raise RuntimeError("failed to bind SRAS-FT gRPC server at %s" % bind_address)
        self._bound_address = "%s:%d" % (self.config.listen_host, bound_port)
        self._server.start()

    def stop(self):
        self._grpc_pool.close()
        server = self._server
        if server is not None:
            server.stop(0)
            self._server = None
            self._bound_address = None

    def bound_address(self):
        if self._bound_address is None:
            raise RuntimeError("FT control server is not started")
        return self._bound_address

    def handle_ping(self, payload):
        return {
            "status": 0,
            "responder_rpe_id": self.config.local_rpe_id,
            "nonce": payload.get("nonce", ""),
        }

    def grpc_post_json(self, address, method, payload, timeout, cancel_event=None):
        return self._grpc_pool.post_json(
            address, method, payload, timeout, cancel_event=cancel_event
        )

    def warmup_peer_channels(self, timeout=2.0, retry_timeout=2.0):
        started = time.perf_counter()
        peer_targets = [
            (peer_id, address)
            for peer_id, address in self.config.peer_addresses.items()
            if peer_id != self.config.local_rpe_id
        ]
        results = {}
        lock = threading.Lock()

        def ping_round(targets, round_timeout, evict_before):
            if not targets:
                return
            if evict_before:
                for _, address in targets:
                    self._grpc_pool.evict(address)
            threads = []

            def ping_one(peer_id, address):
                peer_started = time.perf_counter()
                try:
                    response = self.grpc_post_json(
                        address,
                        "Ping",
                        {"sender_rpe_id": self.config.local_rpe_id, "nonce": self.nonce_factory()},
                        round_timeout,
                    )
                    ok = response.get("status") == 0
                    with lock:
                        results[peer_id] = {
                            "ok": ok,
                            "elapsed_ms": elapsed_ms(peer_started),
                            "error": None if ok else response.get("error", "unknown error"),
                            "retry": evict_before,
                        }
                except Exception as exc:
                    with lock:
                        results[peer_id] = {
                            "ok": False,
                            "elapsed_ms": elapsed_ms(peer_started),
                            "error": str(exc),
                            "retry": evict_before,
                        }

            for peer_id, address in targets:
                thread = threading.Thread(target=ping_one, args=(peer_id, address), daemon=True)
                thread.start()
                threads.append(thread)
            deadline = time.time() + round_timeout
            for thread in threads:
                thread.join(timeout=max(0.0, deadline - time.time()))

        ping_round(peer_targets, timeout, evict_before=False)
        failed_targets = [
            (peer_id, address)
            for peer_id, address in peer_targets
            if not results.get(peer_id, {}).get("ok")
        ]
        if failed_targets:
            logger.info(
                "FT peer channel warmup retrying %d peer(s) after evict: %s",
                len(failed_targets),
                [peer_id for peer_id, _ in failed_targets],
            )
            ping_round(failed_targets, retry_timeout, evict_before=True)

        with lock:
            warmed = sum(1 for item in results.values() if item.get("ok"))
            snapshot = dict(results)
        total_ms = elapsed_ms(started)
        logger.info(
            "FT peer channel warmup finished: warmed=%d/%d elapsed=%.3fms results=%s",
            warmed,
            len(peer_targets),
            total_ms,
            snapshot,
        )
        return {
            "warmed": warmed,
            "total": len(peer_targets),
            "elapsed_ms": total_ms,
            "peers": snapshot,
        }

    def _public_key_from_pem(self, public_key_pem):
        return self._public_key_cache.get_or_load(public_key_pem)

    def _set_peer_public_key(self, rpe_id, public_key_pem):
        old_pem = self.peer_public_keys.get(rpe_id)
        if old_pem != public_key_pem:
            if old_pem:
                self._public_key_cache.invalidate_pem(old_pem)
            self.peer_public_keys[rpe_id] = public_key_pem

    def _peer_public_key(self, rpe_id):
        pem = self.peer_public_keys.get(rpe_id)
        if not pem:
            raise ValueError("unknown peer public key for %s" % rpe_id)
        return self._public_key_from_pem(pem)

    def handle_recovery_query(self, payload):
        recovering_rpe_id = payload.get("recovering_rpe_id")
        recovery_nonce = payload.get("recovery_nonce")
        if not recovering_rpe_id or not recovery_nonce:
            return {"status": 1, "error": "missing recovering_rpe_id or recovery_nonce"}
        recorded = self.state_store.get_recorded_state(recovering_rpe_id)
        if recorded is None:
            recorded_state = self.state_store.zero_attestation_state(recovering_rpe_id)
            logger.info(
                "FT RecoveryQuery from %s: no recorded state on %s; responding with counter=0",
                recovering_rpe_id,
                self.config.local_rpe_id,
            )
        else:
            recorded_state = recorded["state"]
        if self.quote_verifier is None or not hasattr(
            self.quote_verifier, "get_cached_phase2_evidence_for_recovery"
        ):
            return {"status": 1, "error": "cached Phase 2 evidence quote is not configured"}
        logger.info(
            "FT RecoveryQuery from %s: using cached Phase 2 evidence quote (tee=%s counter=%s)",
            recovering_rpe_id,
            recorded_state.get("tee_id"),
            recorded_state.get("attestation_counter"),
        )
        try:
            evidence = self.quote_verifier.get_cached_phase2_evidence_for_recovery()
        except Exception as e:
            logger.error(
                "FT RecoveryQuery from %s: cached Phase 2 evidence quote unavailable: %s",
                recovering_rpe_id,
                str(e),
            )
            return {"status": 1, "error": "cached Phase 2 evidence quote is not available"}
        recovery_state = {
            "responder_rpe_id": self.config.local_rpe_id,
            "recovering_rpe_id": recovering_rpe_id,
            "recorded_attestation_state": recorded_state,
            "recovery_nonce": recovery_nonce,
        }
        logger.info(
            "FT RecoveryQuery accepted for %s; echo sent by %s",
            recovering_rpe_id,
            self.config.local_rpe_id,
        )
        return {
            "status": 0,
            "responder_rpe_id": self.config.local_rpe_id,
            "evidence_quote": evidence["evidence_quote"],
            "rpe_public_signing_key": evidence.get(
                "rpe_public_signing_key", self.signing_public_key_pem
            ),
            "rpe_public_encryption_key": evidence.get("rpe_public_encryption_key", ""),
            "expt_hash": evidence["expt_hash"],
            "recorded_attestation_state": recorded_state,
            "signed_state": {
                "state": recovery_state,
                "signature": sign_json(self.signing_private_key, recovery_state),
            },
            "recovery_nonce": recovery_nonce,
        }

    def handle_evidence_update(self, payload):
        recovering_rpe_id = payload.get("recovering_rpe_id")
        evidence_quote = payload.get("evidence_quote")
        public_key_pem = payload.get("rpe_public_signing_key") or payload.get("rpe_public_key")
        encryption_key_pem = payload.get("rpe_public_encryption_key", "")
        expt_hash = payload.get("expt_hash")
        nonce = payload.get("nonce")
        if (
            not recovering_rpe_id
            or not evidence_quote
            or not public_key_pem
            or not encryption_key_pem
            or not expt_hash
            or not nonce
        ):
            return {"status": 1, "error": "missing evidence update fields"}
        if self.quote_verifier is None:
            return {"status": 1, "error": "quote verifier is not configured"}
        pending_update = {
            "recovering_rpe_id": recovering_rpe_id,
            "evidence_quote": evidence_quote,
            "public_key_pem": public_key_pem,
            "encryption_key_pem": encryption_key_pem,
            "expt_hash": expt_hash,
            "nonce": nonce,
            "received_at": time.time(),
        }
        with self._pending_evidence_updates_lock:
            replaced = recovering_rpe_id in self._pending_evidence_updates
            self._pending_evidence_updates[recovering_rpe_id] = pending_update
            pending_count = len(self._pending_evidence_updates)
        logger.info(
            "FT EvidenceUpdate from %s stored as pending latest update (replaced=%s pending=%d)",
            recovering_rpe_id,
            replaced,
            pending_count,
        )
        return {"status": 0, "content": "pending"}

    def process_pending_evidence_updates(self):
        with self._pending_evidence_updates_lock:
            pending_updates = list(self._pending_evidence_updates.values())
            self._pending_evidence_updates.clear()
        accepted = []
        rejected = []
        for update in pending_updates:
            rpe_id = update["recovering_rpe_id"]
            ok = self._process_evidence_update(
                rpe_id,
                update["evidence_quote"],
                update["public_key_pem"],
                update["encryption_key_pem"],
                update["expt_hash"],
                update["nonce"],
            )
            if ok:
                accepted.append(rpe_id)
            else:
                rejected.append(rpe_id)
        return {
            "processed": len(pending_updates),
            "accepted": accepted,
            "rejected": rejected,
        }

    def _process_evidence_update(
        self,
        recovering_rpe_id,
        evidence_quote,
        public_key_pem,
        encryption_key_pem,
        expt_hash,
        nonce,
    ):
        started = time.perf_counter()
        logger.info("FT EvidenceUpdate from %s pending verification begin", recovering_rpe_id)
        try:
            if not self._verify_evidence_quote(
                evidence_quote,
                public_key_pem,
                encryption_key_pem,
                expt_hash,
                nonce,
                recovering_rpe_id,
            ):
                logger.warning(
                    "FT EvidenceUpdate from %s rejected after %.3fms: evidence quote verification failed",
                    recovering_rpe_id,
                    elapsed_ms(started),
                )
                return False
            self._set_peer_public_key(recovering_rpe_id, public_key_pem)
            if self.on_peer_key_update is not None:
                self.on_peer_key_update(recovering_rpe_id, public_key_pem, encryption_key_pem)
            logger.info(
                "FT EvidenceUpdate from %s accepted in %.3fms; peer public key updated",
                recovering_rpe_id,
                elapsed_ms(started),
            )
            return True
        except Exception as exc:
            logger.warning(
                "FT EvidenceUpdate from %s failed after %.3fms: %s",
                recovering_rpe_id,
                elapsed_ms(started),
                exc,
            )
            return False

    def _verify_evidence_quote(
        self, evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce, rpe_id=None
    ):
        verifier = self.quote_verifier
        if hasattr(verifier, "verify_evidence_quote"):
            try:
                return verifier.verify_evidence_quote(
                    evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce, rpe_id
                )
            except TypeError:
                return verifier.verify_evidence_quote(
                    evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce
                )
        try:
            return verifier(evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce, rpe_id)
        except TypeError:
            return verifier(evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, nonce)

    def _verify_phase2_evidence_quote(
        self, evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, rpe_id=None
    ):
        verifier = self.quote_verifier
        if hasattr(verifier, "verify_phase2_evidence_quote"):
            try:
                return verifier.verify_phase2_evidence_quote(
                    evidence_quote, signing_key_pem, encryption_key_pem, expt_hash, rpe_id
                )
            except TypeError:
                return verifier.verify_phase2_evidence_quote(
                    evidence_quote, signing_key_pem, encryption_key_pem, expt_hash
                )
        return False

    def handle_state_update(self, payload):
        total_started = time.perf_counter()
        sender_rpe_id = payload.get("sender_rpe_id")
        state = payload.get("state")
        if not sender_rpe_id or not isinstance(state, dict):
            logger.warning("FT StateUpdate rejected: missing state update fields")
            return {"status": 1, "error": "missing state update fields"}

        nonce = state.get("nonce")
        if not nonce:
            logger.warning("FT StateUpdate from %s rejected: missing nonce", sender_rpe_id)
            return {"status": 1, "error": "missing nonce"}

        try:
            target_rpe_id = str(state["target_rpe_id"])
            tee_id = str(state["tee_id"])
            attestation_counter = int(state["attestation_counter"])
        except (KeyError, TypeError, ValueError):
            logger.warning("FT StateUpdate from %s rejected: invalid attestation state", sender_rpe_id)
            return {"status": 1, "error": "invalid attestation state"}

        if not target_rpe_id or not tee_id or attestation_counter < 1:
            logger.warning("FT StateUpdate from %s rejected: invalid attestation state", sender_rpe_id)
            return {"status": 1, "error": "invalid attestation state"}

        if not self.state_store.mark_nonce_seen(nonce):
            logger.warning("FT StateUpdate from %s rejected: replayed nonce", sender_rpe_id)
            return {"status": 1, "error": "replayed nonce"}

        record_started = time.perf_counter()
        self.state_store.record_remote_state(state, payload)
        record_state_ms = elapsed_ms(record_started)
        echo = {
            "responder_rpe_id": self.config.local_rpe_id,
            "target_rpe_id": target_rpe_id,
            "tee_id": tee_id,
            "attestation_counter": attestation_counter,
            "nonce": nonce,
        }
        sign_started = time.perf_counter()
        echo["signature"] = sign_json(self.signing_private_key, echo)
        sign_echo_ms = elapsed_ms(sign_started)
        timings = {
            "total_ms": elapsed_ms(total_started),
            "record_state_ms": record_state_ms,
            "sign_echo_ms": sign_echo_ms,
        }
        logger.info(
            "FT StateUpdate accepted from %s for TEE %s counter %d; echo sent by %s "
            "(total=%.3fms record=%.3fms sign_echo=%.3fms)",
            sender_rpe_id,
            tee_id,
            attestation_counter,
            self.config.local_rpe_id,
            timings["total_ms"],
            timings["record_state_ms"],
            timings["sign_echo_ms"],
        )
        return {"status": 0, "echo": echo, "timings": timings}

    def _validate_echo_with_reason(self, echo, expected_state):
        if not isinstance(echo, dict):
            return False, "echo is not a JSON object"
        responder_rpe_id = echo.get("responder_rpe_id")
        signature = echo.get("signature")
        if not responder_rpe_id or not signature:
            return False, "missing responder_rpe_id or signature"
        try:
            if echo.get("nonce") != expected_state["nonce"]:
                return (
                    False,
                    "nonce mismatch (echo=%r expected=%r)"
                    % (echo.get("nonce"), expected_state["nonce"]),
                )
            if echo.get("target_rpe_id") != expected_state["target_rpe_id"]:
                return (
                    False,
                    "target_rpe_id mismatch (echo=%r expected=%r)"
                    % (echo.get("target_rpe_id"), expected_state["target_rpe_id"]),
                )
            if echo.get("tee_id") != expected_state["tee_id"]:
                return (
                    False,
                    "tee_id mismatch (echo=%r expected=%r)"
                    % (echo.get("tee_id"), expected_state["tee_id"]),
                )
            echo_counter = int(echo.get("attestation_counter", -1))
            expected_counter = int(expected_state["attestation_counter"])
            if echo_counter != expected_counter:
                return (
                    False,
                    "attestation_counter mismatch (echo=%r expected=%r)"
                    % (echo_counter, expected_counter),
                )
        except (KeyError, TypeError, ValueError) as exc:
            return False, "invalid echo state fields (%s)" % exc

        signed_echo = dict(echo)
        signed_echo.pop("signature", None)
        try:
            public_key = self._peer_public_key(responder_rpe_id)
        except ValueError as exc:
            return False, "unknown peer public key for %s (%s)" % (responder_rpe_id, exc)
        if not verify_json_signature(public_key, signed_echo, signature):
            return False, "signature verification failed for responder %s" % responder_rpe_id
        return True, None

    def _validate_echo(self, echo, expected_state):
        valid, _reason = self._validate_echo_with_reason(echo, expected_state)
        return valid

    def _build_local_echo(self, state):
        echo = {
            "responder_rpe_id": self.config.local_rpe_id,
            "target_rpe_id": state["target_rpe_id"],
            "tee_id": state["tee_id"],
            "attestation_counter": state["attestation_counter"],
            "nonce": state["nonce"],
        }
        echo["signature"] = sign_json(self.signing_private_key, echo)
        return echo

    def propagate_attestation_state(self, tee_id):
        propagation_perf_started = time.perf_counter()
        counter = self.state_store.next_local_counter(tee_id)
        state = {
            "target_rpe_id": self.config.local_rpe_id,
            "tee_id": str(tee_id),
            "attestation_counter": counter,
            "nonce": random_nonce(),
        }
        request_id = "%s:%s:%s" % (
            self.config.local_rpe_id,
            state["tee_id"],
            state["attestation_counter"],
        )
        update = {
            "sender_rpe_id": self.config.local_rpe_id,
            "state": state,
        }
        sign_echo_started = time.perf_counter()
        local_echo = self._build_local_echo(state)
        local_sign_echo_ms = elapsed_ms(sign_echo_started)
        valid_echoes = [local_echo]
        quorum_target = self.config.ft_quorum
        peer_timings = {}
        peer_targets = [
            (peer_id, address)
            for peer_id, address in self.config.peer_addresses.items()
            if peer_id != self.config.local_rpe_id
        ]
        if not peer_targets:
            logger.info(
                "SRAS-FT state propagation satisfied with local echo for TEE %s counter %d",
                state["tee_id"],
                state["attestation_counter"],
            )
            self.last_propagation_timings = {
                "tee_id": state["tee_id"],
                "attestation_counter": state["attestation_counter"],
                "request_id": request_id,
                "quorum_target": quorum_target,
                "total_ms": elapsed_ms(propagation_perf_started),
                "local_sign_echo_ms": local_sign_echo_ms,
                "peers": peer_timings,
            }
            return len(valid_echoes) >= quorum_target, list(valid_echoes)

        logger.info(
            "SRAS-FT propagating state request_id=%s for TEE %s counter %d with local echo; "
            "need %d/%d echoes from peers %s",
            request_id,
            state["tee_id"],
            state["attestation_counter"],
            max(0, quorum_target - len(valid_echoes)),
            quorum_target,
            [peer_id for peer_id, _ in peer_targets],
        )
        propagation_started_at = time.time()

        threads = []
        lock = threading.Lock()
        stop_event = threading.Event()
        deadline = time.time() + self.config.echo_timeout_sec

        def send_one(peer_id, address):
            if peer_id == self.config.local_rpe_id:
                return
            with lock:
                if _quorum_already_met(stop_event, valid_echoes, quorum_target):
                    return
            remaining_timeout = deadline - time.time()
            if remaining_timeout <= 0:
                return
            peer_timing = {
                "address": address,
                "rpc_total_ms": None,
                "local_verify_echo_ms": None,
                "remote_timings": None,
                "accepted": False,
                "error": None,
            }
            try:
                with lock:
                    if _quorum_already_met(stop_event, valid_echoes, quorum_target):
                        return
                rpc_started = time.perf_counter()
                response = self.grpc_post_json(
                    address,
                    "StateUpdate",
                    update,
                    remaining_timeout,
                    cancel_event=stop_event,
                )
                peer_timing["rpc_total_ms"] = elapsed_ms(rpc_started)
                peer_timing["remote_timings"] = response.get("timings")
                if response.get("status") != 0:
                    peer_timing["error"] = response.get("error", "unknown error")
                    logger.warning(
                        "FT state update to %s rejected: %s",
                        peer_id,
                        response.get("error", "unknown error"),
                    )
                    return
                echo = response.get("echo")
                if echo is None:
                    peer_timing["error"] = "missing echo"
                    logger.warning("FT state update to %s returned no echo", peer_id)
                    return
                with lock:
                    stale_response = (
                        _quorum_already_met(stop_event, valid_echoes, quorum_target)
                        or time.time() >= deadline
                    )
                if stale_response:
                    peer_timing["error"] = "stale response after quorum or timeout"
                    logger.info(
                        "FT state update to %s ignored stale echo for request_id=%s TEE %s counter %d",
                        peer_id,
                        request_id,
                        state["tee_id"],
                        state["attestation_counter"],
                    )
                    return
                verify_echo_started = time.perf_counter()
                echo_valid, echo_reason = self._validate_echo_with_reason(echo, state)
                peer_timing["local_verify_echo_ms"] = elapsed_ms(verify_echo_started)
                if not echo_valid:
                    peer_timing["error"] = echo_reason
                    logger.warning(
                        "FT state update to %s returned invalid echo: %s",
                        peer_id,
                        echo_reason,
                    )
                    return
                with lock:
                    if len(valid_echoes) < quorum_target:
                        valid_echoes.append(echo)
                    peer_timing["accepted"] = True
                    peer_timings[peer_id] = dict(peer_timing)
                    if len(valid_echoes) >= quorum_target:
                        stop_event.set()
                logger.info(
                    "FT state update to %s succeeded for request_id=%s; echo from %s accepted for TEE %s counter %d "
                    "(rpc=%.3fms verify_echo=%.3fms remote=%s)",
                    peer_id,
                    request_id,
                    echo.get("responder_rpe_id"),
                    state["tee_id"],
                    state["attestation_counter"],
                    peer_timing["rpc_total_ms"] or 0.0,
                    peer_timing["local_verify_echo_ms"] or 0.0,
                    peer_timing["remote_timings"],
                )
            except Exception as exc:
                peer_timing["error"] = str(exc)
                logger.warning("FT state update to %s failed: %s", peer_id, exc)
            finally:
                with lock:
                    peer_timings[peer_id] = dict(peer_timing)

        for peer_id, address in peer_targets:
            thread = threading.Thread(target=send_one, args=(peer_id, address), daemon=True)
            thread.start()
            threads.append(thread)

        while time.time() < deadline:
            with lock:
                if len(valid_echoes) >= quorum_target:
                    stop_event.set()
                    break
            any_alive = False
            for thread in threads:
                thread.join(timeout=0.05)
                if thread.is_alive():
                    any_alive = True
            with lock:
                if len(valid_echoes) >= quorum_target:
                    stop_event.set()
                    break
            if not any_alive:
                break

        stop_event.set()
        with lock:
            echoes = list(valid_echoes)
            timings_snapshot = dict(peer_timings)
        met = len(echoes) >= quorum_target
        propagation_duration = time.time() - propagation_started_at
        propagation_duration_ms = elapsed_ms(propagation_perf_started)
        responders = [echo.get("responder_rpe_id") for echo in echoes]
        self.last_propagation_timings = {
            "tee_id": state["tee_id"],
            "attestation_counter": state["attestation_counter"],
            "request_id": request_id,
            "quorum_target": quorum_target,
            "total_ms": propagation_duration_ms,
            "local_sign_echo_ms": local_sign_echo_ms,
            "peers": timings_snapshot,
        }
        if met:
            logger.info(
                "SRAS-FT state propagation quorum reached for request_id=%s TEE %s: %d/%d echoes from %s "
                "in %.3f seconds (%.3fms, local_sign_echo=%.3fms)",
                request_id,
                state["tee_id"],
                len(echoes),
                quorum_target,
                responders,
                propagation_duration,
                propagation_duration_ms,
                local_sign_echo_ms,
            )
        else:
            logger.error(
                "SRAS-FT state propagation quorum not met for request_id=%s TEE %s: %d/%d echoes (responders=%s) after %.3f seconds",
                request_id,
                state["tee_id"],
                len(echoes),
                quorum_target,
                responders,
                propagation_duration,
            )
        return met, echoes

    def _validate_recovery_response(self, response, expected_nonce):
        timings = {
            "evidence_quote_verification_ms": 0.0,
            "signed_state_verification_ms": 0.0,
        }
        responder_rpe_id = response.get("responder_rpe_id")
        if response.get("status") != 0:
            logger.warning(
                "FT recovery response from %s rejected: status=%s error=%s",
                responder_rpe_id or "unknown",
                response.get("status"),
                response.get("error"),
            )
            return None
        if response.get("recovery_nonce") != expected_nonce:
            logger.warning(
                "FT recovery response from %s rejected: recovery_nonce mismatch",
                responder_rpe_id,
            )
            return None
        evidence_quote = response.get("evidence_quote")
        signing_key_pem = response.get("rpe_public_signing_key") or response.get("rpe_public_key")
        encryption_key_pem = response.get("rpe_public_encryption_key", "")
        expt_hash = response.get("expt_hash")
        signed_state = response.get("signed_state")
        if (
            not responder_rpe_id
            or not evidence_quote
            or not signing_key_pem
            or not encryption_key_pem
            or not expt_hash
            or not isinstance(signed_state, dict)
        ):
            logger.warning(
                "FT recovery response from %s rejected: missing required fields",
                responder_rpe_id or "unknown",
            )
            return None
        logger.info("FT recovery validating evidence quote from %s begin", responder_rpe_id)
        evidence_verify_started = time.perf_counter()
        evidence_ok = self._verify_phase2_evidence_quote(
            evidence_quote,
            signing_key_pem,
            encryption_key_pem,
            expt_hash,
            responder_rpe_id,
        )
        timings["evidence_quote_verification_ms"] = elapsed_ms(evidence_verify_started)
        if not evidence_ok:
            logger.warning(
                "FT recovery response from %s rejected: evidence quote verification failed (%.3fms)",
                responder_rpe_id,
                timings["evidence_quote_verification_ms"],
            )
            return None
        logger.info(
            "FT recovery evidence quote from %s ok in %.3fms; validating signed state",
            responder_rpe_id,
            timings["evidence_quote_verification_ms"],
        )

        recovery_state = signed_state.get("state")
        signature = signed_state.get("signature")
        if not isinstance(recovery_state, dict) or not signature:
            return None
        if recovery_state.get("responder_rpe_id") != responder_rpe_id:
            return None
        if recovery_state.get("recovering_rpe_id") != self.config.local_rpe_id:
            return None
        if recovery_state.get("recovery_nonce") != expected_nonce:
            return None
        recorded_state = recovery_state.get("recorded_attestation_state")
        if not isinstance(recorded_state, dict):
            return None
        if recorded_state.get("target_rpe_id") != self.config.local_rpe_id:
            return None
        signed_state_verify_started = time.perf_counter()
        signed_state_ok = verify_json_signature(
            self._public_key_from_pem(signing_key_pem), recovery_state, signature
        )
        timings["signed_state_verification_ms"] = elapsed_ms(signed_state_verify_started)
        if not signed_state_ok:
            logger.warning(
                "FT recovery response from %s rejected: signed state verification failed (%.3fms)",
                responder_rpe_id,
                timings["signed_state_verification_ms"],
            )
            return None
        logger.info(
            "FT recovery response from %s accepted (evidence=%.3fms signed_state=%.3fms)",
            responder_rpe_id,
            timings["evidence_quote_verification_ms"],
            timings["signed_state_verification_ms"],
        )
        return {
            "responder_rpe_id": responder_rpe_id,
            "state": recorded_state,
            "signed_state": signed_state,
            "rpe_public_signing_key": signing_key_pem,
            "rpe_public_encryption_key": encryption_key_pem,
            "expt_hash": expt_hash,
            "timings": timings,
        }

    def recover_latest_attestation_state(self):
        recovery_started = time.perf_counter()
        recovery_nonce = self.nonce_factory()
        raw_responses = []
        failed_peers = []
        valid_responses = []
        validated_peer_ids = set()
        threads = []
        lock = threading.Lock()
        stop_event = threading.Event()
        peer_targets = [
            (peer_id, address)
            for peer_id, address in self.config.peer_addresses.items()
            if peer_id != self.config.local_rpe_id
        ]
        logger.info(
            "FT recover_latest_attestation_state: querying %d peer(s) %s",
            len(peer_targets),
            [peer_id for peer_id, _ in peer_targets],
        )

        def query_one(peer_id, address):
            if peer_id == self.config.local_rpe_id:
                return
            payload = {
                "recovering_rpe_id": self.config.local_rpe_id,
                "recovery_nonce": recovery_nonce,
            }
            peer_started = time.perf_counter()
            try:
                logger.info("FT recovery query to %s begin", peer_id)
                response = self.grpc_post_json(
                    address,
                    "RecoveryQuery",
                    payload,
                    self.config.recovery_timeout_sec,
                    cancel_event=stop_event,
                )
                logger.info(
                    "FT recovery query to %s grpc returned in %.3fms status=%s",
                    peer_id,
                    elapsed_ms(peer_started),
                    response.get("status"),
                )
                with lock:
                    raw_responses.append((peer_id, response, elapsed_ms(peer_started)))
            except Exception as exc:
                logger.warning(
                    "FT recovery query to %s failed after %.3fms: %s",
                    peer_id,
                    elapsed_ms(peer_started),
                    exc,
                )
                with lock:
                    failed_peers.append(peer_id)

        for peer_id, address in peer_targets:
            thread = threading.Thread(target=query_one, args=(peer_id, address), daemon=True)
            thread.start()
            threads.append((peer_id, thread))

        selected = None
        recovery_success_ms = None
        counter_selection_ms = 0.0
        quorum_evidence_ms = 0.0
        quorum_signed_ms = 0.0

        def finalize_quorum_if_ready():
            nonlocal selected, recovery_success_ms, counter_selection_ms
            nonlocal quorum_evidence_ms, quorum_signed_ms
            if recovery_success_ms is not None:
                return
            if len(valid_responses) < self.config.ft_quorum:
                return
            quorum_snapshot = list(valid_responses)
            quorum_ms = elapsed_ms(recovery_started)
            logger.error(
                "====== SRAS-FT recovery QUORUM OK ====== responders=%s elapsed=%.3fs (%.1fms)",
                [response["responder_rpe_id"] for response in quorum_snapshot],
                quorum_ms / 1000.0,
                quorum_ms,
            )
            counter_selection_started = time.perf_counter()
            selected = max(
                quorum_snapshot, key=lambda item: int(item["state"]["attestation_counter"])
            )
            self.state_store.restore_local_counter_floor(
                selected["state"]["tee_id"], int(selected["state"]["attestation_counter"])
            )
            counter_selection_ms = elapsed_ms(counter_selection_started)
            recovery_success_ms = elapsed_ms(recovery_started)
            quorum_evidence_ms = sum(
                response.get("timings", {}).get("evidence_quote_verification_ms", 0.0)
                for response in quorum_snapshot
            )
            quorum_signed_ms = sum(
                response.get("timings", {}).get("signed_state_verification_ms", 0.0)
                for response in quorum_snapshot
            )
            logger.error(
                "====== SRAS-FT recovery SUCCESS ====== tee=%s counter=%s "
                "recovery_success_ms=%.3fs (%.1fms) counter_select=%.1fms",
                selected["state"]["tee_id"],
                selected["state"]["attestation_counter"],
                recovery_success_ms / 1000.0,
                recovery_success_ms,
                counter_selection_ms,
            )
            stop_event.set()

        def validate_pending():
            with lock:
                pending = [
                    (peer_id, response, query_elapsed_ms)
                    for peer_id, response, query_elapsed_ms in raw_responses
                    if peer_id not in validated_peer_ids
                ]
                for peer_id, _, _ in pending:
                    validated_peer_ids.add(peer_id)
            for peer_id, response, query_elapsed_ms in pending:
                validate_started = time.perf_counter()
                valid_response = self._validate_recovery_response(response, recovery_nonce)
                validate_ms = elapsed_ms(validate_started)
                if valid_response is not None:
                    with lock:
                        valid_responses.append(valid_response)
                    logger.info(
                        "FT recovery query to %s accepted (query=%.3fms validate=%.3fms)",
                        peer_id,
                        query_elapsed_ms,
                        validate_ms,
                    )
                    finalize_quorum_if_ready()
                else:
                    logger.warning(
                        "FT recovery query to %s response invalid (query=%.3fms validate=%.3fms)",
                        peer_id,
                        query_elapsed_ms,
                        validate_ms,
                    )

        deadline = time.time() + self.config.recovery_timeout_sec
        while time.time() < deadline:
            validate_pending()
            if recovery_success_ms is not None:
                stop_event.set()
                break
            any_alive = False
            for _, thread in threads:
                thread.join(timeout=0.05)
                if thread.is_alive():
                    any_alive = True
            if not any_alive:
                break
            if recovery_success_ms is not None:
                stop_event.set()
                break

        stop_event.set()
        validate_pending()

        alive_after_join = []
        for peer_id, thread in threads:
            if thread.is_alive():
                remaining = max(0.0, deadline - time.time())
                thread.join(timeout=remaining)
                if thread.is_alive():
                    alive_after_join.append(peer_id)

        validate_pending()
        full_query_collection_ms = elapsed_ms(recovery_started)

        if alive_after_join:
            logger.warning(
                "FT recover_latest_attestation_state: %d query thread(s) timed out after %.3fms (recovery already %s): %s",
                len(alive_after_join),
                full_query_collection_ms,
                "succeeded" if recovery_success_ms is not None else "failed",
                alive_after_join,
            )
        for peer_id in failed_peers:
            logger.warning(
                "FT recover_latest_attestation_state: query to %s failed (recovery already %s)",
                peer_id,
                "succeeded" if recovery_success_ms is not None else "failed",
            )

        responses = list(valid_responses)
        logger.error(
            "====== SRAS-FT RecoveryQuery DONE ====== ok=%s valid=%d/%d "
            "recovery_success=%.3fs full_collection=%.3fs",
            recovery_success_ms is not None,
            len(responses),
            self.config.ft_quorum,
            (recovery_success_ms or 0.0) / 1000.0,
            full_query_collection_ms / 1000.0,
        )
        if recovery_success_ms is None:
            self.last_recovery_timings = {
                "recovery_query_ms": full_query_collection_ms,
                "evidence_quote_verification_ms": sum(
                    response.get("timings", {}).get("evidence_quote_verification_ms", 0.0)
                    for response in responses
                ),
                "signed_state_verification_ms": sum(
                    response.get("timings", {}).get("signed_state_verification_ms", 0.0)
                    for response in responses
                ),
                "counter_selection_ms": 0.0,
                "valid_response_count": len(responses),
                "quorum": self.config.ft_quorum,
                "full_query_collection_ms": full_query_collection_ms,
                "total_recover_latest_ms": full_query_collection_ms,
            }
            return False, None, responses

        for response in responses:
            responder_rpe_id = response["responder_rpe_id"]
            self._set_peer_public_key(responder_rpe_id, response["rpe_public_signing_key"])
            if self.on_peer_key_update is not None:
                self.on_peer_key_update(
                    responder_rpe_id,
                    response["rpe_public_signing_key"],
                    response["rpe_public_encryption_key"],
                )

        self.last_recovery_timings = {
            "recovery_query_ms": recovery_success_ms,
            "recovery_success_ms": recovery_success_ms,
            "evidence_quote_verification_ms": quorum_evidence_ms,
            "signed_state_verification_ms": quorum_signed_ms,
            "counter_selection_ms": counter_selection_ms,
            "valid_response_count": len(responses),
            "quorum": self.config.ft_quorum,
            "selected_tee_id": selected["state"]["tee_id"],
            "selected_attestation_counter": int(selected["state"]["attestation_counter"]),
            "full_query_collection_ms": full_query_collection_ms,
            "total_recover_latest_ms": recovery_success_ms,
        }
        return True, selected, responses

    def _send_evidence_update_one(self, peer_id, address, payload, timeout):
        peer_started = time.perf_counter()
        try:
            logger.info("FT evidence update to %s begin", peer_id)
            response = self.grpc_post_json(address, "EvidenceUpdate", payload, timeout)
            peer_ms = elapsed_ms(peer_started)
            if response.get("status") == 0:
                logger.info(
                    "FT evidence update to %s accepted in %.3fms",
                    peer_id,
                    peer_ms,
                )
                return peer_id
            logger.warning(
                "FT evidence update to %s rejected in %.3fms: %s",
                peer_id,
                peer_ms,
                response.get("error", "unknown error"),
            )
        except Exception as exc:
            logger.warning(
                "FT evidence update to %s failed after %.3fms: %s",
                peer_id,
                elapsed_ms(peer_started),
                exc,
            )
        return None

    def broadcast_evidence_update(self, evidence, stagger_sec=0.3, wait_for_response=False):
        broadcast_started = time.perf_counter()
        nonce = evidence.get("nonce") or self.nonce_factory()
        payload = {
            "recovering_rpe_id": self.config.local_rpe_id,
            "evidence_quote": evidence["evidence_quote"],
            "rpe_public_signing_key": evidence["rpe_public_signing_key"],
            "rpe_public_encryption_key": evidence["rpe_public_encryption_key"],
            "expt_hash": evidence["expt_hash"],
            "nonce": nonce,
        }

        accepted_peers = []
        dispatched_peers = []
        send_index = 0
        async_threads = []
        for peer_id, address in self.config.peer_addresses.items():
            if peer_id == self.config.local_rpe_id:
                continue
            if send_index > 0 and stagger_sec > 0:
                time.sleep(stagger_sec)
            send_index += 1
            dispatched_peers.append(peer_id)
            if wait_for_response:
                accepted = self._send_evidence_update_one(
                    peer_id, address, payload, self.config.recovery_timeout_sec
                )
                if accepted is not None:
                    accepted_peers.append(accepted)
            else:

                def _worker(target_peer_id=peer_id, target_address=address):
                    accepted = self._send_evidence_update_one(
                        target_peer_id, target_address, payload, self.config.recovery_timeout_sec
                    )
                    if accepted is not None:
                        logger.info("FT evidence update async result: %s accepted", target_peer_id)
                    else:
                        logger.warning("FT evidence update async result: %s not accepted", target_peer_id)

                thread = threading.Thread(
                    target=_worker,
                    name="ft-evidence-update-%s" % peer_id,
                    daemon=True,
                )
                thread.start()
                async_threads.append(thread)

        broadcast_ms = elapsed_ms(broadcast_started)
        if wait_for_response:
            logger.error(
                "====== SRAS-FT EvidenceUpdate BROADCAST DONE ====== accepted=%d/%d elapsed=%.3fs (waited)",
                len(accepted_peers),
                send_index,
                broadcast_ms / 1000.0,
            )
            ok = len(accepted_peers) > 0
        else:
            logger.error(
                "====== SRAS-FT EvidenceUpdate BROADCAST DISPATCHED ====== peers=%d elapsed=%.3fs (not waiting)",
                send_index,
                broadcast_ms / 1000.0,
            )
            ok = send_index > 0
            accepted_peers = list(dispatched_peers)

        self.last_recovery_timings["new_quote_broadcast_ms"] = broadcast_ms
        self.last_recovery_timings["evidence_update_peer_count"] = send_index
        self.last_recovery_timings["evidence_update_accepted_count"] = len(accepted_peers)
        self.last_recovery_timings["evidence_update_waited_for_response"] = wait_for_response
        return ok, accepted_peers
