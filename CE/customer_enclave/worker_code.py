import logging
import json
import os
import time
import ctypes
import ratls as RaTLS
import certificate
from crypto_utils import crypto_utility

logger = logging.getLogger(__name__)

class WorkerCode:
    def __init__(self,ratls,rpe_address,rpe_port,collaborative_ce_address,collaborative_ce_port,ce_port,CECert, CEKey):
        self.rpe_ratls = ratls
        self.rpe_address = rpe_address
        self.rpe_port = rpe_port
        self.collaborative_ce_address = collaborative_ce_address
        self.collaborative_ce_port = collaborative_ce_port
        self.ce_port = ce_port
        self.CECert = CECert
        self.CEKey = CEKey

    def test(self):
        # Here is the logic of customer's work code.
        #
        # TODO: worker code here !
        #       Replace here with your code !
        #
        # We only demonstrate the process of building security channel.

        # Build the security channel.
        collaborative_tls = RaTLS.RATLS()

        collaborative_tls.ce_client_init(self.CECert, self.CEKey, self.collaborative_ce_address, self.collaborative_ce_port)
        ServerCERT = collaborative_tls.get_ce_cert_from_client()
        cert = certificate.parse_ce_certificate(ServerCERT)
        certificate.verify_ce_certificate(cert)
        # result = self.rpe_ratls.veritfy_ce_server_cert(crypto_utility.hex_to_base64(ServerCERT))
        # if result=="Agree to build the secure channel!":
        collaborative_tls.ce_client_exchange_data("test ID test")

        # collaborative_tls.ce_server_init(self.CECert, self.CEKey, self.ce_port)
        # ClientCERT = collaborative_tls.get_ce_cert_from_server()
        # certificate.parse_ce_certificate(ClientCERT)
        # result = self.rpe_ratls.veritfy_ce_client_cert(crypto_utility.hex_to_base64(ClientCERT))
        # if result=="Agree to build the secure channel!":
        #   data = collaborative_tls.ce_server_exchange_data()
        #   logger.info("%s",data)

