import logging
import json
import os
import time
import ctypes

RAtlsserver = ctypes.CDLL('./relying_party_owner/RATLS_Conn/libRAtlsserver.so')

logger = logging.getLogger(__name__)

class RATLS:
    def init_measurements(self, mr, mrsigner, isvprodid, isvsvn):
        RAtlsserver.init_measurements.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        # RAtlsserver.init_measurements.restype = ctypes.c_int
        b_mr = mr.encode('utf-8')
        b_mrsigner = mrsigner.encode('utf-8')
        b_isvprodid = isvprodid.encode('utf-8')
        b_isvsvn = isvsvn.encode('utf-8')
        RAtlsserver.init_measurements(ctypes.c_char_p(b_mr), ctypes.c_char_p(b_mrsigner),
                                      ctypes.c_char_p(b_isvprodid), ctypes.c_char_p(b_isvsvn))

    def init_qeid(self, qeid):
        RAtlsserver.init_qeid.argtypes = [ctypes.c_char_p]
        # RAtlsserver.init_measurements.restype = ctypes.c_int
        s = ''.join(str(x+' ') for x in qeid)
        b_qeid = s.encode('utf-8')
        RAtlsserver.init_qeid(ctypes.c_char_p(b_qeid))

    def init_tcb_info(self, tcb_info):
        RAtlsserver.init_tcb_info.argtypes = [ctypes.c_char_p]
        # RAtlsserver.init_measurements.restype = ctypes.c_int
        # s = ''.join(str(x+' ') for x in tcb_info)
        # b_tcb_info = s.encode('utf-8')
        b_tcb_info = tcb_info.encode('utf-8')
        RAtlsserver.init_tcb_info(ctypes.c_char_p(b_tcb_info))
    
    def server_init(self, port):
        try:
            RAtlsserver.server_init.argtypes = [ctypes.c_char_p]
            RAtlsserver.server_init.restype = ctypes.c_int

            b_port = port.encode('utf-8')
            result = RAtlsserver.server_init(ctypes.c_char_p(b_port))

            return result
        
        except Exception as e:
            logger.error(
                "Server_init error"
                " Error message %(message)" % 
                { "message": str(e) })
            raise

    def wait_for_connection(self):
        RAtlsserver.server_accept_connection.argtypes = []
        RAtlsserver.server_accept_connection.restype = ctypes.c_int

        result = RAtlsserver.server_accept_connection()
        return result
    
    def close_connection(self):
        RAtlsserver.server_close_connection.argtypes = []
        RAtlsserver.server_close_connection.restype = ctypes.c_int

        result = RAtlsserver.server_close_connection()
        return result
    
    def perform_handshake(self):
        RAtlsserver.server_perform_handshake.argtypes = []
        RAtlsserver.server_perform_handshake.restype = ctypes.c_int

        result = RAtlsserver.server_perform_handshake()
        return result
    
    def verify_peer(self):
        RAtlsserver.server_verify_peer.argtypes = []
        RAtlsserver.server_verify_peer.restype = ctypes.c_int

        result = RAtlsserver.server_verify_peer()
        return result

    def get_rpe_public_keys(self, signing_key_buf_size=375, encryption_keys_buf_size=651):
        RAtlsserver.handle_get_keys.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
        RAtlsserver.handle_get_keys.restype = ctypes.c_int

        signing_key_buf = ctypes.create_string_buffer(signing_key_buf_size)
        encryption_keys_buf = ctypes.create_string_buffer(encryption_keys_buf_size)

        ret = RAtlsserver.handle_get_keys(signing_key_buf, signing_key_buf_size,
                                              encryption_keys_buf, encryption_keys_buf_size)
        
        if ret != 0:
            logger.error(f"get_rpe_public_keys failed with error code: {ret}")
            return None, None

        return signing_key_buf.value, encryption_keys_buf.value

    def receive_commands(self, buffer_size=1024):
        RAtlsserver.receive_message.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        RAtlsserver.receive_message.restype = ctypes.c_int

        buffer = ctypes.create_string_buffer(buffer_size)
        ret = RAtlsserver.receive_message(buffer, buffer_size)
        if ret > 0:
            return buffer.value.decode('utf-8')
        else:
            logger.error(f"receive_message failed with error code: {ret}")
            return None
            
    def pass_policy_data(self, policies_data, verification_result):
        RAtlsserver.pass_policy_data.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        RAtlsserver.pass_policy_data.restype = ctypes.c_int
        b_policies_data = policies_data.encode('utf-8')
        b_verification_result = verification_result.encode('utf-8')
        ret = RAtlsserver.pass_policy_data(ctypes.c_char_p(b_policies_data), ctypes.c_char_p(b_verification_result))
        return ret

    def server_cleanup(self):
        RAtlsserver.server_cleanup.argtypes = []
        RAtlsserver.server_cleanup.restype

        RAtlsserver.server_cleanup()