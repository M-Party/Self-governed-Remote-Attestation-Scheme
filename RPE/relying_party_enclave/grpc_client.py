from __future__ import print_function

import grpc
import logging
import rpe_pb2
import rpe_pb2_grpc

logger = logging.getLogger(__name__)

class GrpcChannelManager:
    _channels = {}
    
    @staticmethod
    def get_channel(address):
        if address not in GrpcChannelManager._channels:
            channel = grpc.insecure_channel(address, options=[
                ('grpc.keepalive_time_ms', 30000),
                ('grpc.keepalive_timeout_ms', 5000),
                ('grpc.keepalive_permit_without_calls', True),
                ('grpc.http2.max_pings_without_data', 0),
                ('grpc.http2.min_time_between_pings_ms', 10000),
                ('grpc.http2.min_ping_interval_without_data_ms', 300000),
            ])
            GrpcChannelManager._channels[address] = channel
        return GrpcChannelManager._channels[address]

def sendRPEVerificationInfo(address, rpeVerificationInfo):
    if address is None:
        return False
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.SendRPEVerificationInfo(rpe_pb2.RPEVerificationInfo(rpeVerificationInfo=rpeVerificationInfo))
        if response.status != 0:
            logger.error("Fail to send rpe verification info: %s", response.content)
            return False
        return True

def queryRPEs(address, requiredRPENumber):
    if address is None:
        return False, None
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryRPEs(rpe_pb2.RequiredRPENumber(requiredRPENumber=requiredRPENumber))
        if response.status != 0:
            logger.error("Fail to query rpes: %s", response.content)
            return False, None
        return True, response.content

def sendQuote(address, rpeId, base64EncodedQuote):
    if address is None:
        return False
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.SendQuote(rpe_pb2.RpeIdAndQuote(
            rpeId=rpeId,
            base64EncodedQuote=base64EncodedQuote))
        if response.status != 0:
            logger.error("Fail to send Quote: %s", response.content)
            return False
        return True
    
def queryQuote(address, rpeId):
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryQuote(rpe_pb2.RpeId(rpeId=rpeId))
        if response.status != 0:
            logger.error("Fail to query Quote: %s", response.content)
            return False, None
        return True, response.content
    
def queryQuoteByIds(address, rpeIds):
    channel = GrpcChannelManager.get_channel(address)  # 复用 channel
    stub = rpe_pb2_grpc.RpeServiceStub(channel)
    try:
        response = stub.QueryQuoteByIds(rpe_pb2.RpeIds(rpeIds=rpeIds), timeout=30.0)
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
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
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
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryVerificationFinalResult(rpe_pb2.RpeIds(rpeIds=rpeIds))
        if response.status != 0:
            logger.error("Fail to query verificationFinalResult: %s", response.content)
            return False, None
        return True, response.content
    
def sendCEsInfo(address, cesInfo):
    if address is None:
        return False
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.SendCEsInfo(rpe_pb2.CEsInfo(
            cesInfo=cesInfo))
        if response.status != 0:
            logger.error("Fail to send CEs info: %s", response.content)
            return False
        return True
    
def queryCEsInfo(address, jobIds):
    if address is None:
        return False, None
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryCEsInfo(rpe_pb2.JobIds(jobIds=jobIds))
        if response.status != 0:
            logger.error("Fail to query CEs' info: %s", response.content)
            return False, None
        return True, response.content