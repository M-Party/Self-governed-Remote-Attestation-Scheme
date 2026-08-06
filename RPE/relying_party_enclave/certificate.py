import logging
from cryptography import x509
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
import base64
import binascii

logger = logging.getLogger(__name__)


def generate_ce_certificate(private_key, public_key, rpe_id):
    # Define a custom NameOID
    CUSTOM_OID = x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9")

    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Shanghai"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Shang Hai"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Intel Corp"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
        x509.NameAttribute(CUSTOM_OID, rpe_id),
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


def parse_ce_certificate(cert_char):
    pem_certificate = f"-----BEGIN CERTIFICATE-----\n{cert_char}\n-----END CERTIFICATE-----"
    cert = x509.load_pem_x509_certificate(pem_certificate.encode('utf-8'), openssl_backend)
    return cert

def get_ce_certificate_rpeid(certificate):
    CUSTOM_OID = x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9")
    custom_value = certificate.subject.get_attributes_for_oid(CUSTOM_OID)
    return custom_value[0].value


def verify_ce_certificate(certificate, public_key):
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm)
        )
        logger.info("Certificate verification successful.")
    except Exception as e:
        logger.error(f"Certificate verification failed: {e}")
        return "CE certificate verification failed!"

    return "Agree to build the secure channel!"
