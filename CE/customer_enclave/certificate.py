import logging
from cryptography import x509
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
import base64
import binascii

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)

def generate_ce_certificate(private_key, public_key):
    # Generate a private key using ECDSA with P-384 curve
    # private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

    # Generate a public key
    # public_key = private_key.public_key()
    

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Shanghai"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Shang Hai"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Intel Corp"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
    ).sign(private_key, hashes.SHA384(), openssl_backend)
    
    return cert.public_bytes(serialization.Encoding.PEM)

    # Save the private key to a file (for demonstration purposes)
    # with open("private_key.pem", "wb") as private_key_file:
    #     private_key_file.write(
    #         private_key.private_bytes(
    #             encoding=serialization.Encoding.PEM,
    #             format=serialization.PrivateFormat.TraditionalOpenSSL,
    #             encryption_algorithm=serialization.NoEncryption()
    #         )
    #     )

    # # Save the certificate to a file
    # with open("certificate.pem", "wb") as certificate_file:
    #     certificate_file.write(
    #         certificate.public_bytes(serialization.Encoding.PEM)
    #     )

def parse_ce_certificate(cert_char):
    # Convert hex string to bytes
    binary_data = binascii.unhexlify(cert_char)

    # Encode the binary certificate data in base64
    encoded_certificate = base64.b64encode(binary_data).decode('utf-8')

    # Format the base64-encoded certificate as PEM
    pem_certificate = f"-----BEGIN CERTIFICATE-----\n{encoded_certificate}\n-----END CERTIFICATE-----"

    # Print or use the PEM-formatted certificate
    cert = x509.load_pem_x509_certificate(pem_certificate.encode('utf-8'), openssl_backend)

    return cert

def verify_ce_certificate(certificate):
    # loaded_certificate = x509.load_pem_x509_certificate(CECert, openssl_backend)
    
    # Get the public key
    public_key = certificate.public_key()

    # Compare the public key with keys
    

    # Verify the certificate
    try:
        public_key.verify(
            certificate.signature,
            # certificate's TBS (to-be-signed) bytes
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm)
        )
        logger.info("Certificate verification successful.")
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        print(certificate.public_bytes(serialization.Encoding.PEM))
        print(e)
       

  
    


