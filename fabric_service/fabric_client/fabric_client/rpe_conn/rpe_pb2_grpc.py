# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import rpe_pb2 as rpe__pb2


class RpeServiceStub(object):
    """====== RpeService =======
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.SendRPEVerificationInfo = channel.unary_unary(
                '/rpe.RpeService/SendRPEVerificationInfo',
                request_serializer=rpe__pb2.RPEVerificationInfo.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.QueryRPEs = channel.unary_unary(
                '/rpe.RpeService/QueryRPEs',
                request_serializer=rpe__pb2.RequiredRPENumber.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.SendQuote = channel.unary_unary(
                '/rpe.RpeService/SendQuote',
                request_serializer=rpe__pb2.RpeIdAndQuote.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.QueryQuote = channel.unary_unary(
                '/rpe.RpeService/QueryQuote',
                request_serializer=rpe__pb2.RpeId.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.QueryQuoteByIds = channel.unary_unary(
                '/rpe.RpeService/QueryQuoteByIds',
                request_serializer=rpe__pb2.RpeIds.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.SendVerificationResult = channel.unary_unary(
                '/rpe.RpeService/SendVerificationResult',
                request_serializer=rpe__pb2.VerificationResult.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.QueryVerificationFinalResult = channel.unary_unary(
                '/rpe.RpeService/QueryVerificationFinalResult',
                request_serializer=rpe__pb2.RpeIds.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.SendCEsInfo = channel.unary_unary(
                '/rpe.RpeService/SendCEsInfo',
                request_serializer=rpe__pb2.CEsInfo.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )
        self.QueryCEsInfo = channel.unary_unary(
                '/rpe.RpeService/QueryCEsInfo',
                request_serializer=rpe__pb2.JobIds.SerializeToString,
                response_deserializer=rpe__pb2.Response.FromString,
                )


class RpeServiceServicer(object):
    """====== RpeService =======
    """

    def SendRPEVerificationInfo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def QueryRPEs(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SendQuote(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def QueryQuote(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def QueryQuoteByIds(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SendVerificationResult(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def QueryVerificationFinalResult(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SendCEsInfo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def QueryCEsInfo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_RpeServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'SendRPEVerificationInfo': grpc.unary_unary_rpc_method_handler(
                    servicer.SendRPEVerificationInfo,
                    request_deserializer=rpe__pb2.RPEVerificationInfo.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'QueryRPEs': grpc.unary_unary_rpc_method_handler(
                    servicer.QueryRPEs,
                    request_deserializer=rpe__pb2.RequiredRPENumber.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'SendQuote': grpc.unary_unary_rpc_method_handler(
                    servicer.SendQuote,
                    request_deserializer=rpe__pb2.RpeIdAndQuote.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'QueryQuote': grpc.unary_unary_rpc_method_handler(
                    servicer.QueryQuote,
                    request_deserializer=rpe__pb2.RpeId.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'QueryQuoteByIds': grpc.unary_unary_rpc_method_handler(
                    servicer.QueryQuoteByIds,
                    request_deserializer=rpe__pb2.RpeIds.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'SendVerificationResult': grpc.unary_unary_rpc_method_handler(
                    servicer.SendVerificationResult,
                    request_deserializer=rpe__pb2.VerificationResult.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'QueryVerificationFinalResult': grpc.unary_unary_rpc_method_handler(
                    servicer.QueryVerificationFinalResult,
                    request_deserializer=rpe__pb2.RpeIds.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'SendCEsInfo': grpc.unary_unary_rpc_method_handler(
                    servicer.SendCEsInfo,
                    request_deserializer=rpe__pb2.CEsInfo.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
            'QueryCEsInfo': grpc.unary_unary_rpc_method_handler(
                    servicer.QueryCEsInfo,
                    request_deserializer=rpe__pb2.JobIds.FromString,
                    response_serializer=rpe__pb2.Response.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'rpe.RpeService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class RpeService(object):
    """====== RpeService =======
    """

    @staticmethod
    def SendRPEVerificationInfo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/SendRPEVerificationInfo',
            rpe__pb2.RPEVerificationInfo.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def QueryRPEs(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/QueryRPEs',
            rpe__pb2.RequiredRPENumber.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def SendQuote(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/SendQuote',
            rpe__pb2.RpeIdAndQuote.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def QueryQuote(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/QueryQuote',
            rpe__pb2.RpeId.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def QueryQuoteByIds(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/QueryQuoteByIds',
            rpe__pb2.RpeIds.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def SendVerificationResult(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/SendVerificationResult',
            rpe__pb2.VerificationResult.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def QueryVerificationFinalResult(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/QueryVerificationFinalResult',
            rpe__pb2.RpeIds.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def SendCEsInfo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/SendCEsInfo',
            rpe__pb2.CEsInfo.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def QueryCEsInfo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/rpe.RpeService/QueryCEsInfo',
            rpe__pb2.JobIds.SerializeToString,
            rpe__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
