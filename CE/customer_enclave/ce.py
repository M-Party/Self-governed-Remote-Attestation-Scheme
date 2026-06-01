import logging
import ctypes
import sys
import hashlib
from crypto_utils import crypto_utility
from ecdsa import SigningKey, VerifyingKey, NIST384p
from Cryptodome.PublicKey import RSA
from utility import config as pconfig
import ratls as RaTLS
import worker_code
import certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl import backend as openssl_backend

# Load .so
lib = ctypes.CDLL('./customer_enclave/keys_generation/generate_key_pair.so') 
# Define types of params and returns
lib.generate_rsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_rsa_keypair.restype = None
lib.generate_ecdsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_ecdsa_keypair.restype = None

logger = logging.getLogger(__name__)

class RPE:
    def __init__(self):
        self.conf = self.load_conf()
        conf = self.conf["ce"]
        self.signing_keys = None
        self.encryption_keys = None
        self.local_ce = conf["local_ce"]   
        self.rpe_address = conf["rpe_address"]
        self.rpe_port = conf["rpe_port"]
        self.collaborative_ce_address = conf["collaborative_ce_address"]
        self.collaborative_ce_port = conf["collaborative_ce_port"]
        self.ce_port = conf["ce_port"]
    
    def start(self):
        # =============== Phase three ===============
        import time
        import json
        import os
        
        # Performance test: write a flag after CE initialization so phase3 can detect readiness.
        perf_dir = "./performance_data"
        os.makedirs(perf_dir, exist_ok=True)
        pre_connect_flag = os.path.join(perf_dir, "ce_pre_connect_ready_{}.flag".format(self.local_ce))
        start_rpe_flag = os.path.join(perf_dir, "START_RPE_NOW.flag")
        try:
            with open(pre_connect_flag, "w") as f:
                f.write("{}\n".format(time.time()))
            logger.info("CE %s pre-connect ready..." % self.local_ce)
        except Exception as e:
            logger.warning("Failed to write pre-connect flag: %s" % e)
        # Total-time mode: wait for START_RPE_NOW.flag before timing the RPE connection.
        if os.environ.get("CE_WAIT_FOR_START_RPE", "").strip().lower() in ("1", "true", "yes"):
            wait_timeout = 300
            wait_start = time.time()
            while not os.path.isfile(start_rpe_flag):
                if time.time() - wait_start > wait_timeout:
                    logger.error("Timeout waiting for START_RPE_NOW.flag")
                    return
                time.sleep(0.001)
            logger.info("CE %s START_RPE_NOW.flag detected, starting auth timer and connecting to RPE..." % self.local_ce)

        # Performance test: record authentication start time.
        auth_start_time = time.time()
        perf_data = {
            "ce_id": self.local_ce,
            "auth_start": auth_start_time,
            "auth_end": None,
            "auth_duration": None
        }

        init_start_time = time.time()
        # Initialize RA-TLS clent
        ratls = RaTLS.RATLS()
        success = ratls.client(self.rpe_address, self.rpe_port)
        if not success:
            return 
        init_end_time = time.time()
        logger.info("CE %s RA-TLS client initialization completed in %.3f seconds" % (self.local_ce, init_end_time - init_start_time))

        # Get CE certificate from RPE
        cert_start_time = time.time()
        CECertBase64 = ratls.get_cert_from_rpe(self.local_ce)
        cert_end_time = time.time()
        # Performance test: record authentication completion time.
        auth_end_time = time.time()
        auth_duration = auth_end_time - auth_start_time
        cert_duration = cert_end_time - cert_start_time
        
        perf_data["auth_end"] = auth_end_time
        perf_data["auth_duration"] = auth_duration
        perf_data["cert_duration"] = cert_duration
        
        logger.info("CE %s authentication completed in %.3f seconds (cert request: %.3f seconds)" % 
                   (self.local_ce, auth_duration, cert_duration))
        
        # Save performance data.
        perf_dir = "./performance_data"
        os.makedirs(perf_dir, exist_ok=True)
        perf_file = os.path.join(perf_dir, f"ce_perf_{self.local_ce}.json")
        with open(perf_file, 'w') as f:
            json.dump(perf_data, f, indent=2)
        logger.info("Performance data saved to %s" % perf_file)

        exit(0)
        if CECertBase64 is None:
            logger.error("Failed to get CE certificate from RPE")
            return
        CECert = crypto_utility.base64_to_byte_array(CECertBase64)
        # logger.info("CE cert: %s", CECert.decode())
        
        logger.info("======================= Woker Code Running ... =======================")
        # Get peer certificate and send to RPE to verify.
        wc = worker_code.WorkerCode(ratls, self.rpe_address, self.rpe_port, self.collaborative_ce_address, 
                                    self.collaborative_ce_port, self.ce_port, CECert, ratls.signing_private_key)
        wc.test()

    def generate_keys(self):
        private_signing_key = ec.generate_private_key(
                            curve=ec.SECP384R1(),
                            backend=openssl_backend)
        public_signing_key = private_signing_key.public_key()
        self.signing_keys = {
            "public": public_signing_key,
            "private": private_signing_key
        }
        
        private_encryption_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=3072,
                            backend=openssl_backend)
        public_encryption_key = private_encryption_key.public_key()
        self.encryption_keys = {
            "public": public_encryption_key,
            "private": private_encryption_key
        }
        
    def generate_keys_openssl(self):
        
        # Generate secp384r1 ECDSA key pair
        ecdsa_private_pem, ecdsa_public_pem = self.generate_ecdsa_keypair()
        # Generate RSA3072 key pair
        rsa_private_pem, rsa_public_pem = self.generate_rsa_keypair()
        
        # Import rsa and ecdsa key pair
        private_signing_key = SigningKey.from_pem(ecdsa_private_pem, hashfunc=hashlib.sha384)
        public_signing_key = VerifyingKey.from_pem(ecdsa_public_pem, hashfunc=hashlib.sha384)
        self.signing_keys = {
            "public": public_signing_key,
            "private": private_signing_key
        }
        
        private_encryption_key = RSA.import_key(rsa_private_pem)
        public_encryption_key = RSA.import_key(rsa_public_pem)
        self.encryption_keys = {
            "public": public_encryption_key,
            "private": private_encryption_key
        }
        
    def generate_rsa_keypair(self):
        private_pem = ctypes.c_char_p()
        public_pem = ctypes.c_char_p()
        lib.generate_rsa_keypair(ctypes.byref(private_pem), ctypes.byref(public_pem))
        private_pem_str = private_pem.value.decode()
        public_pem_str = public_pem.value.decode()
        lib.free(private_pem)
        lib.free(public_pem)
        return private_pem_str, public_pem_str

    def generate_ecdsa_keypair(self):
        private_pem = ctypes.c_char_p()
        public_pem = ctypes.c_char_p()
        lib.generate_ecdsa_keypair(ctypes.byref(private_pem), ctypes.byref(public_pem))
        private_pem_str = private_pem.value.decode()
        public_pem_str = public_pem.value.decode()
        lib.free(private_pem)
        lib.free(public_pem)
        return private_pem_str, public_pem_str
    
    def load_conf(self):
        try:
            conf = pconfig.parse_configuration_files(
                    ["config.toml"],
                    ["/"])
            return conf
        except pconfig.ConfigurationException as e:
            logger.error(str(e))
            sys.exit(-1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    rpe = RPE()
    rpe.start()
