#!/usr/bin/env python3
"""
轻量级多点直连 P2P Quote 交换服务。

该服务复用 fabric_client 的 gRPC proto 接口，但不依赖 Fabric 账本。
每个参与方启动一个本地节点，节点之间通过简单广播复制状态，用于
Phase 2「移除 Fabric 账本，仅保留 Quote 广播交换」的消融实验。
"""
from concurrent import futures
import argparse
import json
import logging
import threading
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import grpc

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
_FABRIC_CLIENT_ROOT = os.path.join(
    _PROJECT_ROOT, "fabric_service", "fabric_client", "fabric_client"
)
if _FABRIC_CLIENT_ROOT not in sys.path:
    sys.path.insert(0, _FABRIC_CLIENT_ROOT)

from rpe_conn import rpe_pb2  # type: ignore
from rpe_conn import rpe_pb2_grpc  # type: ignore


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_FORWARDED_METADATA_KEY = "x-p2p-forwarded"


def _parse_csv_ids(raw_ids):
    return [item.strip() for item in raw_ids.split(",") if item.strip()]


class InMemoryExchangeState:
    def __init__(self):
        self._lock = threading.Lock()
        self._quotes_condition = threading.Condition(self._lock)
        self.quotes = {}
        self.workers = {}
        self.verification_results = {}
        self.ces_info = {}

    def reset(self):
        with self._lock:
            self.quotes.clear()
            self.workers.clear()
            self.verification_results.clear()
            self.ces_info.clear()

    def set_quote(self, rpe_id, quote):
        with self._quotes_condition:
            self.quotes[rpe_id] = quote
            self._quotes_condition.notify_all()

    def get_quote(self, rpe_id):
        with self._lock:
            return self.quotes.get(rpe_id)

    def get_quotes(self, rpe_ids):
        with self._lock:
            return {rpe_id: self.quotes[rpe_id] for rpe_id in rpe_ids if rpe_id in self.quotes}

    def wait_for_quotes(self, rpe_ids, timeout=None):
        requested_ids = [rpe_id for rpe_id in rpe_ids if rpe_id]
        if not requested_ids:
            return {}, 0, 0.0

        deadline = None if timeout is None else time.time() + timeout
        wait_started_at = time.time()
        with self._quotes_condition:
            while True:
                ready_quotes = {
                    rpe_id: self.quotes[rpe_id]
                    for rpe_id in requested_ids
                    if rpe_id in self.quotes
                }
                if len(ready_quotes) == len(requested_ids):
                    return ready_quotes, len(ready_quotes), time.time() - wait_started_at

                if deadline is not None:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        return ready_quotes, len(ready_quotes), time.time() - wait_started_at
                else:
                    remaining = None

                self._quotes_condition.wait(timeout=remaining)

    def add_worker(self, worker_id, details):
        with self._lock:
            self.workers[worker_id] = details

    def get_workers(self):
        with self._lock:
            return dict(self.workers)

    def set_verification_result(self, rpe_id, result):
        with self._lock:
            self.verification_results[rpe_id] = result

    def get_verification_results(self, rpe_ids):
        with self._lock:
            return {
                rpe_id: self.verification_results.get(rpe_id)
                for rpe_id in rpe_ids
                if rpe_id in self.verification_results
            }

    def set_ces_info(self, ces_info):
        info = json.loads(ces_info)
        with self._lock:
            if isinstance(info, dict):
                self.ces_info.update(info)

    def get_ces_info(self, job_ids):
        with self._lock:
            return {job_id: self.ces_info[job_id] for job_id in job_ids if job_id in self.ces_info}


class PeerBroadcaster:
    def __init__(self, node_id, peer_addresses):
        self.node_id = node_id
        self.peer_addresses = [address for address in peer_addresses if address]
        self._executor = ThreadPoolExecutor(max_workers=max(1, len(self.peer_addresses)))

    @staticmethod
    def _metadata():
        return ((_FORWARDED_METADATA_KEY, "1"),)

    def _send_to_peer(self, peer_address, rpc_name, request):
        request_label = getattr(request, "rpeId", rpc_name)
        max_attempts = 3 if rpc_name == "SendQuote" else 1

        for attempt in range(1, max_attempts + 1):
            try:
                logger.info(
                    "Node %s forwarding %s for %s to %s (attempt %d/%d)",
                    self.node_id,
                    rpc_name,
                    request_label,
                    peer_address,
                    attempt,
                    max_attempts,
                )
                with grpc.insecure_channel(peer_address) as channel:
                    stub = rpe_pb2_grpc.RpeServiceStub(channel)
                    rpc = getattr(stub, rpc_name)
                    response = rpc(request, metadata=self._metadata(), timeout=5.0)
                    if response.status == 0:
                        logger.info(
                            "Node %s forwarded %s for %s to %s successfully",
                            self.node_id,
                            rpc_name,
                            request_label,
                            peer_address,
                        )
                        return

                    logger.warning(
                        "Node %s forwarding %s for %s to %s failed on attempt %d/%d: %s",
                        self.node_id,
                        rpc_name,
                        request_label,
                        peer_address,
                        attempt,
                        max_attempts,
                        response.content,
                    )
            except grpc.RpcError as exc:
                logger.warning(
                    "Node %s forwarding %s for %s to %s rpc error on attempt %d/%d: %s",
                    self.node_id,
                    rpc_name,
                    request_label,
                    peer_address,
                    attempt,
                    max_attempts,
                    exc,
                )

            if attempt < max_attempts:
                time.sleep(0.1 * attempt)

        logger.error(
            "Node %s exhausted retries forwarding %s for %s to %s",
            self.node_id,
            rpc_name,
            request_label,
            peer_address,
        )

    def _fanout(self, rpc_name, request):
        for peer_address in self.peer_addresses:
            self._send_to_peer(peer_address, rpc_name, request)

    def broadcast_rpe_verification_info(self, request):
        self._fanout("SendRPEVerificationInfo", request)

    def broadcast_quote(self, request):
        self._fanout("SendQuote", request)

    def broadcast_quote_async(self, request):
        copied_request = rpe_pb2.RpeIdAndQuote(
            rpeId=request.rpeId,
            base64EncodedQuote=request.base64EncodedQuote,
        )
        for peer_address in self.peer_addresses:
            self._executor.submit(self._send_to_peer, peer_address, "SendQuote", copied_request)

    def broadcast_verification_result(self, request):
        self._fanout("SendVerificationResult", request)

    def broadcast_ces_info(self, request):
        self._fanout("SendCEsInfo", request)


class P2PExchangeService(rpe_pb2_grpc.RpeServiceServicer):
    def __init__(self, state, broadcaster, query_wait_timeout=25.0):
        self.state = state
        self.broadcaster = broadcaster
        self.query_wait_timeout = query_wait_timeout

    @staticmethod
    def _is_forwarded(context):
        metadata = dict(context.invocation_metadata())
        return metadata.get(_FORWARDED_METADATA_KEY) == "1"

    def SendRPEVerificationInfo(self, request, context):
        rpe_verification_info = json.loads(request.rpeVerificationInfo)
        self.state.add_worker(
            rpe_verification_info["rpe_id"],
            rpe_verification_info.get("details", {}),
        )
        if not self._is_forwarded(context):
            self.broadcaster.broadcast_rpe_verification_info(request)
        return rpe_pb2.Response(status=0, content="")

    def QueryRPEs(self, request, context):
        required_rpe_number = request.requiredRPENumber
        while True:
            workers = self.state.get_workers()
            if len(workers) >= required_rpe_number:
                content = json.dumps(
                    [{"worker_id": worker_id, "details": details} for worker_id, details in workers.items()]
                )
                return rpe_pb2.Response(status=0, content=content)
            time.sleep(0.2)

    def SendQuote(self, request, context):
        self.state.set_quote(request.rpeId, request.base64EncodedQuote)
        logger.info(
            "Node %s received quote for %s (forwarded=%s)",
            self.broadcaster.node_id,
            request.rpeId,
            self._is_forwarded(context),
        )
        if not self._is_forwarded(context):
            self.broadcaster.broadcast_quote_async(request)
        return rpe_pb2.Response(status=0, content="")

    def QueryQuote(self, request, context):
        quote = self.state.get_quote(request.rpeId)
        if quote is None:
            return rpe_pb2.Response(status=1, content="quote not found")
        return rpe_pb2.Response(status=0, content=quote)

    def QueryQuoteByIds(self, request, context):
        requested_ids = _parse_csv_ids(request.rpeIds)
        logger.info(
            "Node %s QueryQuoteByIds request: ids=%s",
            self.broadcaster.node_id,
            requested_ids,
        )
        quotes, ready_count, waited_seconds = self.state.wait_for_quotes(
            requested_ids,
            timeout=self.query_wait_timeout,
        )
        logger.info(
            "Node %s QueryQuoteByIds response: ids=%s ready=%d/%d waited=%.3fs returned=%s",
            self.broadcaster.node_id,
            requested_ids,
            ready_count,
            len(requested_ids),
            waited_seconds,
            sorted(quotes.keys()),
        )
        return rpe_pb2.Response(status=0, content=json.dumps(quotes))

    def SendVerificationResult(self, request, context):
        self.state.set_verification_result(request.rpeId, request.verificationResult)
        if not self._is_forwarded(context):
            self.broadcaster.broadcast_verification_result(request)
        return rpe_pb2.Response(status=0, content="")

    def QueryVerificationFinalResult(self, request, context):
        results = self.state.get_verification_results(_parse_csv_ids(request.rpeIds))
        return rpe_pb2.Response(status=0, content=json.dumps(results))

    def SendCEsInfo(self, request, context):
        self.state.set_ces_info(request.cesInfo)
        if not self._is_forwarded(context):
            self.broadcaster.broadcast_ces_info(request)
        return rpe_pb2.Response(status=0, content="")

    def QueryCEsInfo(self, request, context):
        result = self.state.get_ces_info(_parse_csv_ids(request.jobIds))
        return rpe_pb2.Response(status=0, content=json.dumps(result))


def serve(port, node_id, peer_addresses, query_wait_timeout):
    state = InMemoryExchangeState()
    broadcaster = PeerBroadcaster(node_id=node_id, peer_addresses=peer_addresses)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=20))
    rpe_pb2_grpc.add_RpeServiceServicer_to_server(
        P2PExchangeService(state, broadcaster, query_wait_timeout=query_wait_timeout),
        server,
    )
    server.add_insecure_port("0.0.0.0:%d" % port)
    logger.info(
        "Starting P2P node %s on port %d with peers=%s",
        node_id,
        port,
        peer_addresses,
    )
    server.start()
    server.wait_for_termination()


def main():
    parser = argparse.ArgumentParser(description="Multi-peer direct P2P Quote exchange service")
    parser.add_argument("--port", type=int, default=51051, help="gRPC listen port")
    parser.add_argument("--node-id", type=str, default="p2p-node", help="node identifier for logs")
    parser.add_argument(
        "--peer-addresses",
        type=str,
        default="",
        help="comma-separated peer grpc addresses, e.g. 127.0.0.1:51052,127.0.0.1:51053",
    )
    parser.add_argument(
        "--query-wait-timeout",
        type=float,
        default=25.0,
        help="seconds for QueryQuoteByIds to wait for requested quotes before returning partial results",
    )
    args = parser.parse_args()
    serve(args.port, args.node_id, _parse_csv_ids(args.peer_addresses), args.query_wait_timeout)


if __name__ == "__main__":
    main()
