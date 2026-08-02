from __future__ import print_function

import grpc
import logging
import time
import rpe_pb2
import rpe_pb2_grpc

logger = logging.getLogger(__name__)


class GrpcChannelManager:
    _channels = {}
    _stubs = {}

    @staticmethod
    def get_channel(address):
        if address not in GrpcChannelManager._channels:
            GrpcChannelManager._channels[address] = grpc.insecure_channel(address)
        return GrpcChannelManager._channels[address]

    @staticmethod
    def get_stub(address):
        if address not in GrpcChannelManager._stubs:
            channel = GrpcChannelManager.get_channel(address)
            GrpcChannelManager._stubs[address] = rpe_pb2_grpc.RpeServiceStub(channel)
        return GrpcChannelManager._stubs[address]

def sendRPEVerificationInfo(address, rpeVerificationInfo):
    if address is None:
        return False
    stub = GrpcChannelManager.get_stub(address)
    response = stub.SendRPEVerificationInfo(rpe_pb2.RPEVerificationInfo(rpeVerificationInfo=rpeVerificationInfo))
    if response.status != 0:
        logger.error("Fail to send rpe verification info: %s", response.content)
        return False
    return True

def queryRPEs(address, requiredRPENumber):
    if address is None:
        return False, None
    stub = GrpcChannelManager.get_stub(address)
    response = stub.QueryRPEs(rpe_pb2.RequiredRPENumber(requiredRPENumber=requiredRPENumber))
    if response.status != 0:
        logger.error("Fail to query rpes: %s", response.content)
        return False, None
    return True, response.content

def sendQuote(address, rpeId, base64EncodedQuote):
    if address is None:
        return False
    stub = GrpcChannelManager.get_stub(address)
    started_at = time.time()
    logger.error("grpc_client.sendQuote start: address=%s rpeId=%s", address, rpeId)
    response = stub.SendQuote(rpe_pb2.RpeIdAndQuote(
        rpeId=rpeId,
        base64EncodedQuote=base64EncodedQuote))
    finished_at = time.time()
    logger.error(
        "grpc_client.sendQuote done: address=%s rpeId=%s status=%s elapsed=%.3fs",
        address,
        rpeId,
        response.status,
        finished_at - started_at,
    )
    if response.status != 0:
        logger.error("Fail to send Quote: %s", response.content)
        return False
    return True
    
def queryQuote(address, rpeId):
    stub = GrpcChannelManager.get_stub(address)
    response = stub.QueryQuote(rpe_pb2.RpeId(rpeId=rpeId))
    if response.status != 0:
        logger.error("Fail to query Quote: %s", response.content)
        return False, None
    return True, response.content
    
def queryQuoteByIds(address, rpeIds):
    stub = GrpcChannelManager.get_stub(address)
    try:
        started_at = time.time()
        logger.error("grpc_client.queryQuoteByIds start: address=%s rpeIds=%s", address, rpeIds)
        response = stub.QueryQuoteByIds(rpe_pb2.RpeIds(rpeIds=rpeIds), timeout=30.0)
        finished_at = time.time()
        logger.error(
            "grpc_client.queryQuoteByIds done: address=%s status=%s elapsed=%.3fs",
            address,
            response.status,
            finished_at - started_at,
        )
        if response.status != 0:
            logger.error("Fail to query Quotes: %s", response.content)
            return False, None
        return True, response.content
    except grpc.RpcError as e:
        logger.error("gRPC error: %s", e)
        return False, None
    
def sendVerificationResult(address, rpeId, verificationResult):
    if address is None:
        return False
    stub = GrpcChannelManager.get_stub(address)
    response = stub.SendVerificationResult(rpe_pb2.VerificationResult(
        rpeId=rpeId,
        verificationResult=verificationResult))
    if response.status != 0:
        logger.error("Fail to send Verification result: %s", response.content)
        return False
    return True
    
def queryVerificationFinalResult(address, rpeIds):
    if address is None:
        return False, None
    stub = GrpcChannelManager.get_stub(address)
    response = stub.QueryVerificationFinalResult(rpe_pb2.RpeIds(rpeIds=rpeIds))
    if response.status != 0:
        logger.error("Fail to query verificationFinalResult: %s", response.content)
        return False, None
    return True, response.content
    
def sendCEsInfo(address, cesInfo):
    if address is None:
        return False
    stub = GrpcChannelManager.get_stub(address)
    response = stub.SendCEsInfo(rpe_pb2.CEsInfo(
        cesInfo=cesInfo))
    if response.status != 0:
        logger.error("Fail to send CEs info: %s", response.content)
        return False
    return True
    
def queryCEsInfo(address, jobIds):
    if address is None:
        return False, None
    stub = GrpcChannelManager.get_stub(address)
    response = stub.QueryCEsInfo(rpe_pb2.JobIds(jobIds=jobIds))
    if response.status != 0:
        logger.error("Fail to query CEs' info: %s", response.content)
        return False, None
    return True, response.content


_POLICY_RPE_ID_PREFIX = "policy:"


def _policy_storage_id(rpe_id):
    if rpe_id.startswith(_POLICY_RPE_ID_PREFIX):
        return rpe_id
    return _POLICY_RPE_ID_PREFIX + rpe_id


def sendPolicy(address, rpeId, base64EncodedPolicy):
    """Exchange full expectation policy via the existing Quote channel.

    Storage key is prefixed so policy blobs never collide with Evidence Quotes.
    """
    return sendQuote(address, _policy_storage_id(rpeId), base64EncodedPolicy)


def queryPolicyByIds(address, rpeIds):
    """Query policies for CSV rpe ids; returns (ok, json_dict_str keyed by bare rpe id)."""
    if isinstance(rpeIds, str):
        bare_ids = [item.strip() for item in rpeIds.split(",") if item.strip()]
    else:
        bare_ids = list(rpeIds)
    storage_ids = ",".join(_policy_storage_id(rpe_id) for rpe_id in bare_ids)
    ok, content = queryQuoteByIds(address, storage_ids)
    if not ok or content is None:
        return False, None
    import json
    stored = json.loads(content)
    out = {}
    for key, value in stored.items():
        bare = key[len(_POLICY_RPE_ID_PREFIX):] if key.startswith(_POLICY_RPE_ID_PREFIX) else key
        out[bare] = value
    return True, json.dumps(out)
