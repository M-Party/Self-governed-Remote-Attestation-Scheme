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


def load_public_key_pem(public_key_pem):
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    return serialization.load_pem_public_key(public_key_pem, backend=openssl_backend)


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
            recovery_timeout_sec=float(_as_str(ft_conf.get("recovery_timeout_sec"), "5")),
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
        self._server = None
        self._bound_address = None

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
        server = self._server
        if server is not None:
            server.stop(0)
            self._server = None
            self._bound_address = None

    def bound_address(self):
        if self._bound_address is None:
            raise RuntimeError("FT control server is not started")
        return self._bound_address

    def grpc_post_json(self, address, method, payload, timeout):
        channel = grpc.insecure_channel(address)
        rpc = channel.unary_unary(
            "/%s/%s" % (FT_GRPC_SERVICE, method),
            request_serializer=lambda value: value,
            response_deserializer=lambda value: value,
        )
        response_bytes = rpc(canonical_json_bytes(payload), timeout=timeout)
        return json.loads(response_bytes.decode("utf-8"))

    def _peer_public_key(self, rpe_id):
        pem = self.peer_public_keys.get(rpe_id)
        if not pem:
            raise ValueError("unknown peer public key for %s" % rpe_id)
        return load_public_key_pem(pem)

    def handle_recovery_query(self, payload):
        recovering_rpe_id = payload.get("recovering_rpe_id")
        recovery_nonce = payload.get("recovery_nonce")
        if not recovering_rpe_id or not recovery_nonce:
            return {"status": 1, "error": "missing recovering_rpe_id or recovery_nonce"}
        recorded = self.state_store.get_recorded_state(recovering_rpe_id)
        if recorded is None:
            return {"status": 1, "error": "no recorded state for recovering RPE"}
        if self.quote_verifier is None or not hasattr(self.quote_verifier, "generate_evidence_quote"):
            return {"status": 1, "error": "quote generator is not configured"}
        evidence = self.quote_verifier.generate_evidence_quote(recovery_nonce)
        recovery_state = {
            "responder_rpe_id": self.config.local_rpe_id,
            "recovering_rpe_id": recovering_rpe_id,
            "recorded_attestation_state": recorded["state"],
            "recovery_nonce": recovery_nonce,
        }
        return {
            "status": 0,
            "responder_rpe_id": self.config.local_rpe_id,
            "evidence_quote": evidence["evidence_quote"],
            "rpe_public_signing_key": evidence.get(
                "rpe_public_signing_key", self.signing_public_key_pem
            ),
            "rpe_public_encryption_key": evidence.get("rpe_public_encryption_key", ""),
            "expt_hash": evidence["expt_hash"],
            "recorded_attestation_state": recorded["state"],
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
        if not self._verify_evidence_quote(
            evidence_quote,
            public_key_pem,
            encryption_key_pem,
            expt_hash,
            nonce,
            recovering_rpe_id,
        ):
            return {"status": 1, "error": "evidence quote verification failed"}
        self.peer_public_keys[recovering_rpe_id] = public_key_pem
        if self.on_peer_key_update is not None:
            self.on_peer_key_update(recovering_rpe_id, public_key_pem, encryption_key_pem)
        return {"status": 0, "content": ""}

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

    def handle_state_update(self, payload):
        sender_rpe_id = payload.get("sender_rpe_id")
        state = payload.get("state")
        signature = payload.get("signature")
        if not sender_rpe_id or not isinstance(state, dict) or not signature:
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

        if not verify_json_signature(self._peer_public_key(sender_rpe_id), state, signature):
            logger.warning("FT StateUpdate from %s rejected: invalid state signature", sender_rpe_id)
            return {"status": 1, "error": "invalid state signature"}
        if not self.state_store.mark_nonce_seen(nonce):
            logger.warning("FT StateUpdate from %s rejected: replayed nonce", sender_rpe_id)
            return {"status": 1, "error": "replayed nonce"}

        self.state_store.record_remote_state(state, payload)
        echo = {
            "responder_rpe_id": self.config.local_rpe_id,
            "target_rpe_id": target_rpe_id,
            "tee_id": tee_id,
            "attestation_counter": attestation_counter,
            "nonce": nonce,
        }
        echo["signature"] = sign_json(self.signing_private_key, echo)
        logger.info(
            "FT StateUpdate accepted from %s for TEE %s counter %d; echo sent by %s",
            sender_rpe_id,
            tee_id,
            attestation_counter,
            self.config.local_rpe_id,
        )
        return {"status": 0, "echo": echo}

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
        counter = self.state_store.next_local_counter(tee_id)
        state = {
            "target_rpe_id": self.config.local_rpe_id,
            "tee_id": str(tee_id),
            "attestation_counter": counter,
            "nonce": random_nonce(),
        }
        update = {
            "sender_rpe_id": self.config.local_rpe_id,
            "state": state,
            "signature": sign_json(self.signing_private_key, state),
        }
        local_echo = self._build_local_echo(state)
        valid_echoes = [local_echo]
        quorum_target = self.config.ft_quorum
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
            return len(valid_echoes) >= quorum_target, list(valid_echoes)

        logger.info(
            "SRAS-FT propagating state for TEE %s counter %d with local echo; need %d/%d echoes from peers %s",
            state["tee_id"],
            state["attestation_counter"],
            max(0, quorum_target - len(valid_echoes)),
            quorum_target,
            [peer_id for peer_id, _ in peer_targets],
        )
        propagation_started_at = time.time()

        threads = []
        lock = threading.Lock()

        def send_one(peer_id, address):
            if peer_id == self.config.local_rpe_id:
                return
            try:
                response = self.grpc_post_json(
                    address, "StateUpdate", update, self.config.echo_timeout_sec
                )
                if response.get("status") != 0:
                    logger.warning(
                        "FT state update to %s rejected: %s",
                        peer_id,
                        response.get("error", "unknown error"),
                    )
                    return
                echo = response.get("echo")
                if echo is None:
                    logger.warning("FT state update to %s returned no echo", peer_id)
                    return
                echo_valid, echo_reason = self._validate_echo_with_reason(echo, state)
                if not echo_valid:
                    logger.warning(
                        "FT state update to %s returned invalid echo: %s",
                        peer_id,
                        echo_reason,
                    )
                    return
                with lock:
                    if len(valid_echoes) < quorum_target:
                        valid_echoes.append(echo)
                logger.info(
                    "FT state update to %s succeeded; echo from %s accepted for TEE %s counter %d",
                    peer_id,
                    echo.get("responder_rpe_id"),
                    state["tee_id"],
                    state["attestation_counter"],
                )
            except Exception as exc:
                logger.warning("FT state update to %s failed: %s", peer_id, exc)

        for peer_id, address in peer_targets:
            thread = threading.Thread(target=send_one, args=(peer_id, address), daemon=True)
            thread.start()
            threads.append(thread)

        deadline = time.time() + self.config.echo_timeout_sec
        while time.time() < deadline:
            with lock:
                if len(valid_echoes) >= quorum_target:
                    break
            any_alive = False
            for thread in threads:
                thread.join(timeout=0.05)
                if thread.is_alive():
                    any_alive = True
            with lock:
                if len(valid_echoes) >= quorum_target:
                    break
            if not any_alive:
                break

        with lock:
            echoes = list(valid_echoes)
        met = len(echoes) >= quorum_target
        propagation_duration = time.time() - propagation_started_at
        responders = [echo.get("responder_rpe_id") for echo in echoes]
        if met:
            logger.info(
                "SRAS-FT state propagation quorum reached for TEE %s: %d/%d echoes from %s in %.3f seconds",
                state["tee_id"],
                len(echoes),
                quorum_target,
                responders,
                propagation_duration,
            )
        else:
            logger.error(
                "SRAS-FT state propagation quorum not met for TEE %s: %d/%d echoes (responders=%s) after %.3f seconds",
                state["tee_id"],
                len(echoes),
                quorum_target,
                responders,
                propagation_duration,
            )
        return met, echoes

    def _validate_recovery_response(self, response, expected_nonce):
        if response.get("status") != 0:
            return None
        if response.get("recovery_nonce") != expected_nonce:
            return None
        responder_rpe_id = response.get("responder_rpe_id")
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
            return None
        if not self._verify_evidence_quote(
            evidence_quote,
            signing_key_pem,
            encryption_key_pem,
            expt_hash,
            expected_nonce,
            responder_rpe_id,
        ):
            return None

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
        if not verify_json_signature(load_public_key_pem(signing_key_pem), recovery_state, signature):
            return None
        return {
            "responder_rpe_id": responder_rpe_id,
            "state": recorded_state,
            "signed_state": signed_state,
            "rpe_public_signing_key": signing_key_pem,
            "rpe_public_encryption_key": encryption_key_pem,
            "expt_hash": expt_hash,
        }

    def recover_latest_attestation_state(self):
        recovery_nonce = self.nonce_factory()
        valid_responses = []
        threads = []
        lock = threading.Lock()

        def query_one(peer_id, address):
            if peer_id == self.config.local_rpe_id:
                return
            payload = {
                "recovering_rpe_id": self.config.local_rpe_id,
                "recovery_nonce": recovery_nonce,
            }
            try:
                response = self.grpc_post_json(
                    address, "RecoveryQuery", payload, self.config.recovery_timeout_sec
                )
                valid_response = self._validate_recovery_response(response, recovery_nonce)
                if valid_response is not None:
                    with lock:
                        valid_responses.append(valid_response)
            except Exception as exc:
                logger.warning("FT recovery query to %s failed: %s", peer_id, exc)

        for peer_id, address in self.config.peer_addresses.items():
            thread = threading.Thread(target=query_one, args=(peer_id, address), daemon=True)
            thread.start()
            threads.append(thread)

        deadline = time.time() + self.config.recovery_timeout_sec
        for thread in threads:
            remaining = max(0.0, deadline - time.time())
            thread.join(timeout=remaining)

        with lock:
            responses = list(valid_responses)
        if len(responses) < self.config.ft_quorum:
            return False, None, responses

        for response in responses:
            responder_rpe_id = response["responder_rpe_id"]
            self.peer_public_keys[responder_rpe_id] = response["rpe_public_signing_key"]
            if self.on_peer_key_update is not None:
                self.on_peer_key_update(
                    responder_rpe_id,
                    response["rpe_public_signing_key"],
                    response["rpe_public_encryption_key"],
                )

        selected = max(responses, key=lambda item: int(item["state"]["attestation_counter"]))
        self.state_store.restore_local_counter_floor(
            selected["state"]["tee_id"], int(selected["state"]["attestation_counter"])
        )
        return True, selected, responses

    def broadcast_evidence_update(self, evidence):
        nonce = evidence.get("nonce") or self.nonce_factory()
        payload = {
            "recovering_rpe_id": self.config.local_rpe_id,
            "evidence_quote": evidence["evidence_quote"],
            "rpe_public_signing_key": evidence["rpe_public_signing_key"],
            "rpe_public_encryption_key": evidence["rpe_public_encryption_key"],
            "expt_hash": evidence["expt_hash"],
            "nonce": nonce,
        }
        accepted = []
        threads = []
        lock = threading.Lock()

        def send_one(peer_id, address):
            if peer_id == self.config.local_rpe_id:
                return
            try:
                response = self.grpc_post_json(
                    address, "EvidenceUpdate", payload, self.config.recovery_timeout_sec
                )
                if response.get("status") == 0:
                    with lock:
                        accepted.append(peer_id)
            except Exception as exc:
                logger.warning("FT evidence update to %s failed: %s", peer_id, exc)

        for peer_id, address in self.config.peer_addresses.items():
            thread = threading.Thread(target=send_one, args=(peer_id, address), daemon=True)
            thread.start()
            threads.append(thread)

        deadline = time.time() + self.config.recovery_timeout_sec
        for thread in threads:
            remaining = max(0.0, deadline - time.time())
            thread.join(timeout=remaining)

        with lock:
            peers = list(accepted)
        return len(peers) >= self.config.ft_quorum, peers
