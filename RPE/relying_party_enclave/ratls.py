import logging
import json
import os
import time
import ctypes

RAtls = ctypes.CDLL('./relying_party_enclave/RATLS_Conn/libRAtls.so')

logger = logging.getLogger(__name__)

class RATLS:
    def __init__(self):
        # self.signing_keys = "aaa"
        # self.encryption_keys = "bbb"
        self.rpo_address = None
        self.port = None

    def set_public_keys(self, signing_key, encryption_keys):
        RAtls.send_public_keys.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        RAtls.send_public_keys.restype = ctypes.c_int
        b_address = self.rpo_address.encode('utf-8')
        b_port = self.port.encode('utf-8')
        return RAtls.send_public_keys(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port), 
                                      ctypes.c_char_p(signing_key), ctypes.c_char_p(encryption_keys))

    def client(self, address, port):
        self.rpo_address = address
        self.port = port
        RAtls.ra_tls_client.restype = ctypes.c_int

        ret = RAtls.ra_tls_client()
        if ret != 0:
            logger.error("\n")
            logger.error(" Client initialize failed !")
            return False

        return True

    def get_policies(self, verification_result_size=100):
        RAtls.get_policies.argtypes = [ctypes.c_char_p, ctypes.c_char_p, 
                                       ctypes.c_char_p, ctypes.c_size_t]
        RAtls.get_policies.restype = ctypes.c_char_p

        b_address = self.rpo_address.encode('utf-8')
        b_port = self.port.encode('utf-8')
        verification_result = ctypes.create_string_buffer(verification_result_size)
        
        policies_data = RAtls.get_policies(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port), 
                                           verification_result, verification_result_size)
        
        return ctypes.string_at(policies_data).decode(), verification_result.value.decode()

    def getCEMR(self):
        RAtls.get_ce_mr.argtypes = []
        RAtls.get_ce_mr.restype = ctypes.c_char_p

        result = RAtls.get_ce_mr()
        return ctypes.string_at(result).decode()
    
    
    def getCEMRSigner(self):
        RAtls.get_ce_mrsigner.argtypes = []
        RAtls.get_ce_mrsigner.restype = ctypes.c_char_p

        result = RAtls.get_ce_mrsigner()
        return ctypes.string_at(result).decode()
    
    def getCEISVProdid(self):
        RAtls.get_ce_isvprodid.argtypes = []
        RAtls.get_ce_isvprodid.restype = ctypes.c_char_p

        result = RAtls.get_ce_isvprodid()
        return ctypes.string_at(result).decode()
    
    def getCEISVSvn(self):
        RAtls.get_ce_isvsvn.argtypes = []
        RAtls.get_ce_isvsvn.restype = ctypes.c_char_p

        result = RAtls.get_ce_isvsvn()
        return ctypes.string_at(result).decode()


    def getCEQEid(self):
        RAtls.get_ce_qeid.argtypes = []
        RAtls.get_ce_qeid.restype = ctypes.c_char_p

        result = RAtls.get_ce_qeid()
        return ctypes.string_at(result).hex()
        
    def getTCBid(self):
        RAtls.get_tcb_id.argtypes = []
        RAtls.get_tcb_id.restype = ctypes.c_char_p

        result = RAtls.get_tcb_id()
        return ctypes.string_at(result).decode()
    
    def get_ce_id(self):
        RAtls.get_ce_id.argtypes = []
        RAtls.get_ce_id.restype = ctypes.c_char_p

        result = RAtls.get_ce_id()
        return ctypes.string_at(result).decode()

    def init_tcb_info(self, tcb_info):
        RAtls.init_tcb_info.argtypes = [ctypes.c_char_p]
        
        s = tcb_info
        b_tcb_info = s.encode('utf-8')
        RAtls.init_tcb_info(ctypes.c_char_p(b_tcb_info))
    
    def server_init(self, port):
        try:
            RAtls.ra_tls_server_init.argtypes = [ctypes.c_char_p]
            RAtls.ra_tls_server_init.restype = ctypes.c_int

            b_port = port.encode('utf-8')
            result = RAtls.ra_tls_server_init(ctypes.c_char_p(b_port))

            return result

        except Exception as e:
            logger.error(
                "server_init error"
                " Error message %(message)" % 
                {"message": str(e) })
            raise

    def wait_for_connection(self):
        RAtls.server_accept_connection.argtypes = []
        RAtls.server_accept_connection.restype = ctypes.c_int

        return RAtls.server_accept_connection()

    def perform_handshake(self):
        RAtls.server_perform_handshake.argtypes = []
        RAtls.server_perform_handshake.restype = ctypes.c_int

        return RAtls.server_perform_handshake()

    def verify_peer(self):
        RAtls.server_verify_peer.argtypes = []
        RAtls.server_verify_peer.restype = ctypes.c_int

        return RAtls.server_verify_peer()

    def close_connection(self):
        RAtls.server_close_connection.argtypes = []
        RAtls.server_close_connection.restype = ctypes.c_int

        return RAtls.server_close_connection()

    def get_ce_info(self):
        RAtls.handle_ce_info.argtypes = []
        RAtls.handle_ce_info.restype = ctypes.c_int

        return RAtls.handle_ce_info()

    def send_ce_cert(self, ce_cert):
        RAtls.handle_issue_cert.argtypes = [ctypes.c_char_p]
        RAtls.handle_issue_cert.restype = ctypes.c_int
        b_ce_cert = ce_cert.encode('utf-8')
        return RAtls.handle_issue_cert(ctypes.c_char_p(b_ce_cert))

    def get_ce_cert_pubkey_pem(self):
        RAtls.get_ce_cert_pubkey_pem.argtypes = []
        RAtls.get_ce_cert_pubkey_pem.restype = ctypes.c_char_p

        return RAtls.get_ce_cert_pubkey_pem()
   
    def get_collaborative_ce_cert(self):
        RAtls.handle_get_cert.argtypes = []
        RAtls.handle_get_cert.restype = ctypes.c_char_p
        result = RAtls.handle_get_cert()
        return ctypes.string_at(result).decode()
        
    def send_verification_result(self, verification_result):
        RAtls.handle_verification_result.argtypes = [ctypes.c_char_p]
        RAtls.handle_verification_result.restype = ctypes.c_int
        b_verification_result = verification_result.encode('utf-8')
        return RAtls.handle_verification_result(ctypes.c_char_p(b_verification_result))

    def verify_ce_body(self, ces_info):
        # {'job-1': {'rpe': 'rpe-1', 
        #            'cust_qeid_allowed': ['first qeid'], 
        #            'tcb_allowed': ['tcb-1'], 
        #            'mrenclave_allow_any': True, 
        #            'mrsigner_allow_any': True, 
        #            'isvprodid_allow_any': True, 
        #            'isvsvn_allow_any': True}, 
        #  'job-2': {'rpe': 'rpe-1', 
        #            'cust_qeid_allowed': ['second qeid'], 
        #            'tcb_allowed': ['tcb-1'], 
        #            'mrenclave': '4ea60548cce6f25ab0b02c6f326d33222bdd74e73df817a39fbbd2af562f77bd', 
        #            'mrsigner': 'mrsigner value', 
        #            'isv_prod_id': '0', 
        #            'isv_svn': '0'}, 
        #  'job-3': {'rpe': 'rpe-2', 
        #            'cust_qeid_allowed': ['third qeid', 'efbac5bb8d8cd796a8379405e5e846e2'], 
        #            'tcb_allowed': ['tcb-1', 'tcb-2'], 
        #            'mrenclave': '4ea60548cce6f25ab0b02c6f326d33222bdd74e73df817a39fbbd2af562f77bd', 
        #            'mrsigner': 'mrsigner value', 
        #            'isv_prod_id': '0', 
        #            'isv_svn': '0'}
        # }

        # {'job-2': {'rpe': 'rpe-1', 
        #            'cust_qeid_allowed': ['second qeid', 'efbac5bb8d8cd796a8379405e5e846e2'], 
        #            'tcb_allowed': ['tcb-1'], 
        #            'mrenclave': '4ea60548cce6f25ab0b02c6f326d33222bdd74e73df817a39fbbd2af562f77bd', 
        #            'mrsigner': 'mrsigner value', 
        #            'isv_prod_id': '0', 
        #            'isv_svn': '0'}
        # }
        for key in ces_info.keys():
            # verify ce mr
            if 'mrenclave' in ces_info[key].keys() and self.getCEMR() != ces_info[key]['mrenclave']:
                logger.error(" CE mr verification failed !")
                logger.info("mrenclave: %s", self.getCEMR())
                return -1
            elif 'mrenclave_allow_any' in ces_info[key].keys() and ces_info[key]['mrenclave_allow_any'] != True:
                logger.error(" CE mr verification failed !")
                return -1
            
            if 'mrsigner' in ces_info[key].keys() and self.getCEMRSigner() != ces_info[key]['mrsigner']:
                logger.error(" CE mrsigner verification failed !")
                return -1
            elif "mrsigner_allow_any" in ces_info[key].keys() and ces_info[key]['mrsigner_allow_any'] != True:
                logger.error(" CE mrsigner verification failed !")
                return -1
            
            if 'isv_prod_id' in ces_info[key].keys() and self.getCEISVProdid() != ces_info[key]['isv_prod_id'] and ces_info[key]['isv_prod_id'] != "0":
                logger.error(" CE isv_prod_id verification failed !")
                return -1
            elif "isvprodid_allow_any" in ces_info[key].keys() and ces_info[key]['isvprodid_allow_any'] != True:
                logger.error(" CE isv_prod_id verification failed !")
                return -1
            
            if 'isv_svn' in ces_info[key].keys() and self.getCEISVSvn() != ces_info[key]['isv_svn'] and ces_info[key]['isv_svn'] != "0":
                logger.error(" CE isv_svn verification failed !")
                return -1
            elif "isvsvn_allow_any" in ces_info[key].keys() and ces_info[key]['isvsvn_allow_any'] != True:
                logger.error(" CE isv_svn verification failed !")
                return -1
            
            # verify ce qeid
            flag = False
            for id in ces_info[key]['cust_qeid_allowed']:
                if id == self.getCEQEid():
                    flag = True
                    break
            if flag is False:
                logger.info(" CE qe id verification failed !")
                return -1

        return 1