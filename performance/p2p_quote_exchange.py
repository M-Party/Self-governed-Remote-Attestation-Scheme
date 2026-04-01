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
        with self._lock:
            self.quotes[rpe_id] = quote

    def get_quote(self, rpe_id):
        with self._lock:
            return self.quotes.get(rpe_id)

    def get_quotes(self, rpe_ids):
        with self._lock:
            return {rpe_id: self.quotes[rpe_id] for rpe_id in rpe_ids if rpe_id in self.quotes}

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

    @staticmethod
    def _metadata():
        return ((_FORWARDED_METADATA_KEY, "1"),)

    def _fanout(self, rpc_name, request):
        for peer_address in self.peer_addresses:
            try:
                with grpc.insecure_channel(peer_address) as channel:
                    stub = rpe_pb2_grpc.RpeServiceStub(channel)
                    rpc = getattr(stub, rpc_name)
                    response = rpc(request, metadata=self._metadata(), timeout=5.0)
                    if response.status != 0:
                        logger.warning(
                            "Node %s forwarding %s to %s failed: %s",
                            self.node_id,
                            rpc_name,
                            peer_address,
                            response.content,
                        )
            except grpc.RpcError as exc:
                logger.warning(
                    "Node %s forwarding %s to %s rpc error: %s",
                    self.node_id,
                    rpc_name,
                    peer_address,
                    exc,
                )

    def broadcast_rpe_verification_info(self, request):
        self._fanout("SendRPEVerificationInfo", request)

    def broadcast_quote(self, request):
        self._fanout("SendQuote", request)

    def broadcast_verification_result(self, request):
        self._fanout("SendVerificationResult", request)

    def broadcast_ces_info(self, request):
        self._fanout("SendCEsInfo", request)


class P2PExchangeService(rpe_pb2_grpc.RpeServiceServicer):
    def __init__(self, state, broadcaster):
        self.state = state
        self.broadcaster = broadcaster

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
        if not self._is_forwarded(context):
            self.broadcaster.broadcast_quote(request)
        return rpe_pb2.Response(status=0, content="")

    def QueryQuote(self, request, context):
        quote = self.state.get_quote(request.rpeId)
        if quote is None:
            return rpe_pb2.Response(status=1, content="quote not found")
        return rpe_pb2.Response(status=0, content=quote)

    def QueryQuoteByIds(self, request, context):
        quotes = self.state.get_quotes(_parse_csv_ids(request.rpeIds))
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


def serve(port, node_id, peer_addresses):
    state = InMemoryExchangeState()
    broadcaster = PeerBroadcaster(node_id=node_id, peer_addresses=peer_addresses)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=20))
    rpe_pb2_grpc.add_RpeServiceServicer_to_server(P2PExchangeService(state, broadcaster), server)
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
    args = parser.parse_args()
    serve(args.port, args.node_id, _parse_csv_ids(args.peer_addresses))


if __name__ == "__main__":
    main()
