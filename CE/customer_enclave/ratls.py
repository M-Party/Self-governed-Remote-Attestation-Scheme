import logging
import json
import os
import time
import ctypes

RAtlsclient = ctypes.CDLL('./customer_enclave/RATLS_Conn/libRAtlsclient.so')

logger = logging.getLogger(__name__)

class RATLS:
    def __init__(self):
        self.signing_private_key = None
        # self.encryption_keys = "bbb"
        self.rpe_address = None
        self.port = None
        # self.rpes = None

    def client(self, address, port):
        self.rpe_address = address
        self.port = port
        RAtlsclient.ra_tls_client.restype = ctypes.c_int

        ret = RAtlsclient.ra_tls_client()
        if ret != 0:
            logger.error("\n")
            logger.error(" RA-TLS client initialization failed !")
            return False
        self.signing_private_key = self.get_der_key()
        
        return True

    def get_cert_from_rpe(self, ce_id):
        RAtlsclient.get_cert_from_rpe.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        RAtlsclient.get_cert_from_rpe.restype = ctypes.c_char_p

        b_address = self.rpe_address.encode('utf-8')
        b_port = self.port.encode('utf-8')
        b_ce_id = ce_id.encode('utf-8')

        result = RAtlsclient.get_cert_from_rpe(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port),
                                               ctypes.c_char_p(b_ce_id))
        if result is None:
            logger.error(" Get cert from RPE failed !")
            return None

        return ctypes.string_at(result).decode()

    def veritfy_peer_cert(self, peer_cert, verification_result_size=100):
        RAtlsclient.veritfy_peer_cert.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        RAtlsclient.veritfy_peer_cert.restype = ctypes.c_char_p

        b_address = self.rpe_address.encode('utf-8')
        b_port = self.port.encode('utf-8')
        b_data = peer_cert.encode('utf-8')
        verification_result = ctypes.create_string_buffer(verification_result_size)
           
        ret = RAtlsclient.veritfy_peer_cert(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port), ctypes.c_char_p(b_data), 
                                               verification_result, verification_result_size)
        return ret, verification_result.value.decode()

    def get_der_key(self):
        RAtlsclient.get_der_key.restype = ctypes.c_char_p

        return RAtlsclient.get_der_key()
    
    def ce_client_init(self, CECert, CEKey, address, port):
        if address == "" or port == "":
            logger.error("collaborative_ce_address or collaborative_ce_port is not null value!")
            exit()
        if CEKey is None:
            logger.error(" CE signing private key is not initialized! Please call client() first!")
            exit()

        RAtlsclient.ce_client_init.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        RAtlsclient.ce_client_init.restype = ctypes.c_int

        b_address = address.encode('utf-8')
        b_port = port.encode('utf-8')
    
        result = RAtlsclient.ce_client_init(ctypes.c_char_p(CECert), ctypes.c_char_p(CEKey), ctypes.c_char_p(b_address), ctypes.c_char_p(b_port))
        
        if result != 0:
            logger.error(" CE client initialization failed !")
            exit()
    def get_ce_cert_from_client(self):
        RAtlsclient.get_ce_client_cert.restype = ctypes.c_char_p
        result = RAtlsclient.get_ce_client_cert()
        return ctypes.string_at(result).decode()
    def ce_client_exchange_data(self, data):
        RAtlsclient.ce_client_exchange_data.argtypes = [ctypes.c_char_p]
        RAtlsclient.ce_client_exchange_data.restype = ctypes.c_int

        b_data = data.encode('utf-8')
        result = RAtlsclient.ce_client_exchange_data(ctypes.c_char_p(b_data))

        if result != 0:
            logger.error(" Exchange data failed !")
            exit()

    def ce_server_init(self, CECert, CEKey, port):
        if port == "":
            logger.error("ce_port is not null value!")
            exit()
        if CEKey is None:
            logger.error(" CE signing private key is not initialized! Please call client() first!")
            exit()

        RAtlsclient.ce_server_init.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        RAtlsclient.ce_server_init.restype = ctypes.c_int

        b_port = port.encode('utf-8')
    
        result = RAtlsclient.ce_server_init(ctypes.c_char_p(CECert), ctypes.c_char_p(CEKey), ctypes.c_char_p(b_port))
        if result != 0:
            logger.error(" CE server initialization failed !")
            exit()
    def ce_server_cert_verification(self):
        None
    def get_ce_cert_from_server(self):
        RAtlsclient.get_ce_server_cert.restype = ctypes.c_char_p
        result = RAtlsclient.get_ce_server_cert()
        return ctypes.string_at(result).decode()
    def ce_server_exchange_data(self):
        RAtlsclient.ce_server_exchange_data.restype = ctypes.c_char_p

        result = RAtlsclient.ce_server_exchange_data()
        edata = ctypes.string_at(result).decode()
        return edata


