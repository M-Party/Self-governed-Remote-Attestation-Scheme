import base64
import binascii
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)


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
            expt_cache_path=_as_str(ft_conf.get("expt_cache_path"), "performance_data/expt_cache.json"),
            counter_cache_path=_as_str(
                ft_conf.get("counter_cache_path"), "performance_data/ft_counter_cache.json"
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
