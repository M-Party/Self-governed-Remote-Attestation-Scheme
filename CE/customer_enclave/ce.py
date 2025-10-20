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
        # Generate signing keys and encryption keys
        logger.info("Generating keys...")
        self.generate_keys()
        public_signing_key_pem = self.signing_keys["public"].public_bytes(encoding=serialization.Encoding.PEM, 
                                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)
        private_signing_key_pem = self.signing_keys["private"].private_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                             encryption_algorithm=serialization.NoEncryption())
        public_encryption_key_pem = self.encryption_keys["public"].public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        logger.info("public signing key:\n%s" % public_signing_key_pem.decode())
        logger.info("public signing key size:%d" % len(public_signing_key_pem))
        logger.info("public encryption key:\n%s" % public_encryption_key_pem.decode())
        logger.info("public encryption key size:%d" % len(public_encryption_key_pem))
        logger.info("done.")
        ratls = RaTLS.RATLS()
        
        # =============== Phase three ===============
        # logger.info("======================= Starting ... =======================")
        # # RA-TLS to RPE
        # ratls.initCEID(self.local_ce)
        # ratls.initpublickeys(public_signing_key_pem, public_encryption_key_pem)
        # success = ratls.sendKeys2RPE(self.rpe_address, self.rpe_port)
        
        # # Get CE certificate
        # # Get its own certificate signed by local RPE.
        # CECert = None
        # if success:
        #     CECertBase64 = ratls.getCECert()
        #     CECert = crypto_utility.base64_to_byte_array(CECertBase64)
        # logger.info("CE cert: %s", CECert.decode())

        # ################################# DELETE ############################################
       
        CECert = certificate.generate_ce_certificate(self.signing_keys["private"], self.signing_keys["public"])
        
        # ############################### DELETE END ##########################################

        # =============== Phase four ===============
        logger.info("======================= Woker Code Running ... =======================")
        # Worker Code
        wc = worker_code.WorkerCode(ratls, self.rpe_address, self.rpe_port, self.collaborative_ce_address, 
                                    self.collaborative_ce_port, self.ce_port, CECert, private_signing_key_pem)
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