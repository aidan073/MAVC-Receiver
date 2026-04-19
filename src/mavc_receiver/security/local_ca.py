from .cfg_parser import LocalCaCfg, load_local_ca_cfg, resolve_local_ca_paths

import os
import ipaddress
from pathlib import Path
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization


# ===== Helpers =====
def ensure_dirs(cfg: LocalCaCfg) -> None:
    p = resolve_local_ca_paths(cfg)
    p.certs_dir.mkdir(parents=True, exist_ok=True)
    p.private_dir.mkdir(parents=True, exist_ok=True)
    p.newcerts_dir.mkdir(parents=True, exist_ok=True)

    p.index_path.touch(exist_ok=True)
    if not p.serial_path.exists():
        p.serial_path.write_text("1000")


def save_private_key(key: rsa.RSAPrivateKey, path: Path):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    os.chmod(path, 0o600)


def load_or_create_ca_key(cfg: LocalCaCfg) -> rsa.RSAPrivateKey:
    p = resolve_local_ca_paths(cfg)
    if p.ca_key_path.exists():
        return serialization.load_pem_private_key(
            p.ca_key_path.read_bytes(),
            password=None,
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    save_private_key(key, p.ca_key_path)
    return key


def create_ca_cert(ca_key: rsa.RSAPrivateKey, cfg: LocalCaCfg) -> x509.Certificate:
    p = resolve_local_ca_paths(cfg)
    if p.ca_cert_path.exists():
        return x509.load_pem_x509_certificate(p.ca_cert_path.read_bytes())

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Robot-Local-CA")]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=cfg.ca_validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    p.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def _server_san_for_cfg(cfg: LocalCaCfg) -> x509.SubjectAlternativeName:
    bind_host, bind_port = cfg.server_san_host, cfg.server_san_port
    general_names: list[x509.GeneralName] = []
    try:
        addr = ipaddress.ip_address(bind_host)
        general_names.append(x509.IPAddress(addr))
    except ValueError:
        general_names.append(x509.DNSName(bind_host))
    general_names.append(
        x509.UniformResourceIdentifier(f"tcp://{bind_host}:{bind_port}")
    )
    return x509.SubjectAlternativeName(general_names)


def load_or_create_server_key(cfg: LocalCaCfg) -> rsa.RSAPrivateKey:
    p = resolve_local_ca_paths(cfg)
    if p.server_key_path.exists():
        return serialization.load_pem_private_key(
            p.server_key_path.read_bytes(),
            password=None,
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_private_key(key, p.server_key_path)
    return key


def create_server_cert(
    server_key: rsa.RSAPrivateKey,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    local_ca_cfg: LocalCaCfg,
) -> x509.Certificate:
    p = resolve_local_ca_paths(local_ca_cfg)
    if p.server_cert_path.exists():
        return x509.load_pem_x509_certificate(p.server_cert_path.read_bytes())

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "robot-server")])

    san = _server_san_for_cfg(local_ca_cfg)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(
            datetime.utcnow() + timedelta(days=local_ca_cfg.server_cert_validity_days)
        )
        .add_extension(san, critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    p.server_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def sign_client_csr(
    csr_pem: bytes,
    ca_key: rsa.RSAPublicKey,
    ca_cert: x509.Certificate,
    *,
    local_ca_cfg: LocalCaCfg | None = None,
) -> bytes:
    csr = x509.load_pem_x509_csr(csr_pem)

    if not csr.is_signature_valid:
        raise ValueError("[MAVC-Receiver] Invalid CSR signature")

    validity_days = (
        local_ca_cfg.client_cert_validity_days if local_ca_cfg is not None else 365
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM)


# ===== Main setup =====
def setup_ca_system(local_ca_cfg: Path | str | LocalCaCfg):
    if isinstance(local_ca_cfg, (Path, str)):
        local_ca_cfg = load_local_ca_cfg(Path(local_ca_cfg))
    if not isinstance(local_ca_cfg, LocalCaCfg):
        raise ValueError(
            "[MAVC-Receiver] Argument 'local_ca_cfg' must be a path to a local CA YAML file "
            f"or a LocalCaCfg instance, not {type(local_ca_cfg)}."
        )

    ensure_dirs(local_ca_cfg)
    paths = resolve_local_ca_paths(local_ca_cfg)

    ca_key = load_or_create_ca_key(local_ca_cfg)
    ca_cert = create_ca_cert(ca_key, local_ca_cfg)

    server_key = load_or_create_server_key(local_ca_cfg)
    create_server_cert(server_key, ca_key, ca_cert, local_ca_cfg=local_ca_cfg)

    print("CA and server certificates ready.")
    print(f"CA cert: {paths.ca_cert_path}")
    print(f"Server cert: {paths.server_cert_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        raise SystemExit(
            "usage: python -m mavc_receiver.security.local_ca <local_ca_cfg.yaml>\n"
        )
    setup_ca_system(sys.argv[1])
