import os
from pathlib import Path
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

# ===== Config =====
CA_DIR = Path("ca")
CERTS_DIR = CA_DIR / "certs"
PRIVATE_DIR = CA_DIR / "private"
NEWCERTS_DIR = CA_DIR / "newcerts"

DAYS_CA = 3650
DAYS_SERVER = 825

CA_KEY_PATH = PRIVATE_DIR / "ca.key.pem"
CA_CERT_PATH = CERTS_DIR / "ca.cert.pem"

SERVER_KEY_PATH = PRIVATE_DIR / "server.key.pem"
SERVER_CERT_PATH = CERTS_DIR / "server.cert.pem"
SERVER_CSR_PATH = CA_DIR / "server.csr.pem"


# ===== Helpers =====
def ensure_dirs() -> None:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    NEWCERTS_DIR.mkdir(parents=True, exist_ok=True)

    (CA_DIR / "index.txt").touch(exist_ok=True)
    serial = CA_DIR / "serial"
    if not serial.exists():
        serial.write_text("1000")


def save_private_key(key: rsa.RSAPrivateKey, path: Path):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    os.chmod(path, 0o600)


def load_or_create_ca_key() -> rsa.RSAPrivateKey:
    if CA_KEY_PATH.exists():
        return serialization.load_pem_private_key(
            CA_KEY_PATH.read_bytes(),
            password=None,
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    save_private_key(key, CA_KEY_PATH)
    return key


def create_ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    if CA_CERT_PATH.exists():
        return x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Robot-Local-CA")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=DAYS_CA))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def load_or_create_server_key() -> rsa.RSAPrivateKey:
    if SERVER_KEY_PATH.exists():
        return serialization.load_pem_private_key(
            SERVER_KEY_PATH.read_bytes(),
            password=None,
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_private_key(key, SERVER_KEY_PATH)
    return key


def create_server_cert(server_key: rsa.RSAPrivateKey, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate):
    if SERVER_CERT_PATH.exists():
        return x509.load_pem_x509_certificate(SERVER_CERT_PATH.read_bytes())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "robot-server")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=DAYS_SERVER))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    SERVER_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


# ===== Main setup =====
def setup_ca_system():
    ensure_dirs()

    # CA
    ca_key = load_or_create_ca_key()
    ca_cert = create_ca_cert(ca_key)

    # Server
    server_key = load_or_create_server_key()
    server_cert = create_server_cert(server_key, ca_key, ca_cert)

    print("CA and server certificates ready.")
    print(f"CA cert: {CA_CERT_PATH}")
    print(f"Server cert: {SERVER_CERT_PATH}")


if __name__ == "__main__":
    setup_ca_system()