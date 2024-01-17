import logging
import json
import os
import time
import ctypes

RAtlsclient = ctypes.CDLL('./customer_enclave/RATLS_Conn/libRAtlsclient.so')

logger = logging.getLogger(__name__)

class RATLS:
    def __init__(self):
        # self.signing_keys = "aaa"
        # self.encryption_keys = "bbb"
        # self.rpe_address = '192.168.122.50:50051'
        # self.local_rpe = None
        # self.rpes = None
        self.data = None

    def initpublickeys(self, signing_key, encryption_keys):
        RAtlsclient.init_pubkeys.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        #RAtlsclient.init_pubkeys.restype = ctypes.c_char_p

        RAtlsclient.init_pubkeys(ctypes.c_char_p(signing_key), ctypes.c_char_p(encryption_keys))

    def initCEID(self, ce_id):
        RAtlsclient.init_ce_id.argtypes = [ctypes.c_char_p]
        #RAtlsclient.init_pubkeys.restype = ctypes.c_char_p
        b_ce_id = ce_id.encode('utf-8')  

        RAtlsclient.init_ce_id(ctypes.c_char_p(b_ce_id))
    
    def sendKeys2RPE(self, address, port):
        try:
            RAtlsclient.ra_tls_client.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            RAtlsclient.ra_tls_client.restype = ctypes.c_char_p

            b_address = address.encode('utf-8')
            b_port = port.encode('utf-8')
           
            result = RAtlsclient.ra_tls_client(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port))
            self.data = ctypes.string_at(result).decode()
            # RAtlsclient.free(result)
            if self.data == "None":
                logger.error(" RA connection failed !")
                return False

            return True

        except Exception as e:
            logger.error(
                "Send keys to RPE error"
                " Error message %(message)" % 
                {"message": str(e) })
            raise
            
    def getCECert(self):
        return self.data
    
    def veritfy_ce_server_cert(self,ServerCERT):
        return self.read_write_data_from(ServerCERT)
    def veritfy_ce_client_cert(self,ClientCERT):
        return self.read_write_data_from(ClientCERT)

    def read_write_data_from(self,data):
        RAtlsclient.read_write_data_from.argtypes = [ctypes.c_char_p]
        RAtlsclient.read_write_data_from.restype = ctypes.c_char_p

        b_data = data.encode('utf-8')
           
        result = RAtlsclient.read_write_data_from(ctypes.c_char_p(b_data))
        return ctypes.string_at(result).decode()

    
    def ce_client_init(self, CECert, CEKey, address, port):
        if address == "" or port == "":
            logger.error("collaborative_ce_address or collaborative_ce_port is not null value!")
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


