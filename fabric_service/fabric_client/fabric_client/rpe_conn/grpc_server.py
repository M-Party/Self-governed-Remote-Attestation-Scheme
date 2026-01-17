from concurrent import futures
import logging
import json
import time
import asyncio

import grpc
from . import rpe_pb2
from . import rpe_pb2_grpc
import fabric_connection
from cfl_conf import load_conf

logger = logging.getLogger(__name__)

class RpeService(rpe_pb2_grpc.RpeServiceServicer):
    def __init__(self, fabric_client):
        self.fabric_client = fabric_client
    
    def _ensure_event_loop(self):
        """为当前线程确保有事件循环（Fabric SDK 需要）"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("Event loop is closed")
        except RuntimeError:
            # 当前线程没有事件循环，创建一个
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop
    
    def SendRPEVerificationInfo(self, request, context):
        self._ensure_event_loop()  # 确保有事件循环
        logger.info("RPEVerificationInfo: %s" % request.rpeVerificationInfo)
        rpe_verification_info = json.loads(request.rpeVerificationInfo)
        worker = {
            "worker_id": rpe_verification_info["rpe_id"],
            "organization_id": "",
            "application_type_id": "",
            "details": rpe_verification_info["details"]
        }
        if self.fabric_client.add_worker(worker):
            status = 0
        else:
            status = 1
        return rpe_pb2.Response(status=status, content="")
    
    def QueryRPEs(self, request, context):
        self._ensure_event_loop()
        required_rpe_number = request.requiredRPENumber
        rpe_ids = self.fabric_client.worker_lookup()
        while len(rpe_ids) < required_rpe_number:
            logger.info("RPE in fabric: %d (required is %d), waiting for 3s" % (len(rpe_ids), required_rpe_number))
            time.sleep(3)
            rpe_ids = self.fabric_client.worker_lookup()
        logger.info("RPE in fabric: %d, getting the details" % len(rpe_ids))
        
        rpes = self.fabric_client.get_workers_detail(rpe_ids)
        if len(rpes) == len(rpe_ids):
            status = 0
            content = json.dumps(rpes)
        else:
            status = 1
            content = "Can not get some of the rpes' detail info"
        return rpe_pb2.Response(status=status, content=content)
    
    def SendQuote(self, request, context):
        self._ensure_event_loop()  # 确保有事件循环
        logger.info("Quote: %s" % request.base64EncodedQuote)
        if self.fabric_client.upload_quote(request.rpeId, request.base64EncodedQuote):
            status = 0
        else:
            status = 1
        return rpe_pb2.Response(status=status, content="")
    
    def QueryQuote(self, request, context):
        self._ensure_event_loop()
        quote = self.fabric_client.get_quote(request.rpeId)
        return rpe_pb2.Response(status=0, content=quote)
    
    def QueryQuoteByIds(self, request, context):
        self._ensure_event_loop()  # 确保有事件循环
        try:
            quote_dict = self.fabric_client.get_quote_by_ids(request.rpeIds)
            quotes = json.dumps(quote_dict)
            return rpe_pb2.Response(status=0, content=quotes)
        except Exception as e:
            logger.error("Error in QueryQuoteByIds: %s", str(e))
            return rpe_pb2.Response(status=1, content=str(e))
    
    def SendVerificationResult(self, request, context):
        self._ensure_event_loop()
        if self.fabric_client.upload_verify_result(request.rpeId, request.verificationResult):
            status = 0
        else:
            status = 1
        return rpe_pb2.Response(status=status, content="")

    def QueryVerificationFinalResult(self, request, context):
        self._ensure_event_loop()
        verificationFinalResultJson = self.fabric_client.get_verify_final_result(request.rpeIds)
        verificationFinalResult = json.dumps(verificationFinalResultJson)
        return rpe_pb2.Response(status=0, content=verificationFinalResult)
    
    def SendCEsInfo(self, request, context):
        self._ensure_event_loop()
        if self.fabric_client.upload_customer_enclaves(request.cesInfo):
            status = 0
        else:
            status = 1
        return rpe_pb2.Response(status=status, content="")
    
    def QueryCEsInfo(self, request, context):
        self._ensure_event_loop()
        CEsInfoJson = self.fabric_client.get_customer_enclaves(request.jobIds)
        CEsInfo = json.dumps(CEsInfoJson)
        return rpe_pb2.Response(status=0, content=CEsInfo)

def serve():
    conf = load_conf()
    fabric_client = fabric_connection.Connector(conf)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=20))
    rpe_pb2_grpc.add_RpeServiceServicer_to_server(RpeService(fabric_client), server)
    server.add_insecure_port('[::]:' + conf['grpc']['port'])
    logger.info("starting listen...")
    server.start()
    server.wait_for_termination()