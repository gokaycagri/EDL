import os
import logging
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import datetime

# Define certificate paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(BASE_DIR, "threat_feed_aggregator", "certs")
CERT_FILE = os.path.join(CERTS_DIR, "cert.pem")
KEY_FILE = os.path.join(CERTS_DIR, "key.pem")

# Ensure certs directory exists
if not os.path.exists(CERTS_DIR):
    os.makedirs(CERTS_DIR)

def generate_self_signed_cert():
    """Generates a self-signed certificate if one doesn't exist."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return CERT_FILE, KEY_FILE

    print("Generating self-signed certificate...")
    
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Istanbul"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Istanbul"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Threat Feed Aggregator"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valid for 10 years
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # Write private key to file
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Write certificate to file
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificate generated at {CERT_FILE}")
    return CERT_FILE, KEY_FILE

def process_pfx_upload(pfx_data, password):
    """
    Extracts the private key and certificate from a PFX file.
    Overwrites the existing cert.pem and key.pem files.
    """
    try:
        # Load the PKCS12 data
        if isinstance(password, str):
            password = password.encode()
            
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            pfx_data,
            password
        )

        if not private_key or not certificate:
            raise ValueError("PFX file must contain both a private key and a certificate.")

        # Save private key
        with open(KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Save certificate (and chain if present)
        with open(CERT_FILE, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
            if additional_certificates:
                for cert in additional_certificates:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return True, "Certificate uploaded successfully. Please restart the application."
    except Exception as e:
        logging.error(f"Error processing PFX: {e}")
        return False, str(e)

def get_cert_paths():
    return CERT_FILE, KEY_FILE
