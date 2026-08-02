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

# Custom OID for consensus policy hash H(π*) carried in CE certificates.
CONSENSUS_POLICY_HASH_OID = x509.ObjectIdentifier("1.2.3.4.5.6.7.8.888")


def generate_ce_certificate(private_key, public_key, rpe_id, consensus_policy_hash=None):
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

    builder = x509.CertificateBuilder().subject_name(
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
    )
    if consensus_policy_hash:
        # UnrecognizedExtension carries opaque bytes; store UTF-8 hex of H(π*).
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                CONSENSUS_POLICY_HASH_OID,
                consensus_policy_hash.encode("utf-8")
                if isinstance(consensus_policy_hash, str)
                else consensus_policy_hash,
            ),
            critical=False,
        )
    cert = builder.sign(private_key, hashes.SHA384(), openssl_backend)

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
    # binary_data = binascii.unhexlify(cert_char)

    # Encode the binary certificate data in base64
    # encoded_certificate = base64.b64encode(binary_data).decode('utf-8')

    # Format the base64-encoded certificate as PEM
    pem_certificate = f"-----BEGIN CERTIFICATE-----\n{cert_char}\n-----END CERTIFICATE-----"

    # Print or use the PEM-formatted certificate
    cert = x509.load_pem_x509_certificate(pem_certificate.encode('utf-8'), openssl_backend)
    return cert

def get_ce_certificate_rpeid(certificate):
    # Define a custom NameOID
    CUSTOM_OID = x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9")

    # Retrieve and verify the custom NameOID value
    custom_value = certificate.subject.get_attributes_for_oid(CUSTOM_OID)
    return custom_value[0].value

def get_consensus_policy_hash(certificate):
    """Return H(π*) hex string from certificate extension, or None."""
    try:
        ext = certificate.extensions.get_extension_for_oid(CONSENSUS_POLICY_HASH_OID)
        value = ext.value.value
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return value
    except x509.ExtensionNotFound:
        return None


def verify_ce_certificate(certificate, public_key, expected_consensus_policy_hash=None):

    # Get the public key
    # public_key = certificate.public_key()    

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
        logger.error(f"Certificate verification failed: {e}")
        return "CE certificate verification failed!"

    if expected_consensus_policy_hash is not None:
        actual = get_consensus_policy_hash(certificate)
        if actual is None:
            logger.error("hash_mismatch: certificate missing consensus_policy_hash extension")
            return "CE certificate consensus policy hash missing!"
        expected = (
            expected_consensus_policy_hash
            if isinstance(expected_consensus_policy_hash, str)
            else expected_consensus_policy_hash.hex()
        )
        if actual != expected:
            logger.error(
                "hash_mismatch: certificate H(π*)=%s local H(π*)=%s",
                actual,
                expected,
            )
            return "CE certificate consensus policy hash mismatch!"

    return "Agree to build the secure channel!"