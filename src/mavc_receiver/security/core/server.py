from ...enum import CertStatus
from ..cfg_parser import LocalCaCfg
from .ca import (
    _CA_FILE_LOCK,
    _append_index_line,
    _name_to_openssl_dn,
    _next_serial_number,
    _write_newcert_copy,
    save_private_key,
)

import ipaddress
from cryptography import x509
from datetime import UTC, datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization


def _server_san_for_cfg(cfg: LocalCaCfg) -> x509.SubjectAlternativeName:
    """
    Build Subject Alternative Names for the TLS server cert (bind host, port URI).

    Args:
        cfg (LocalCaCfg): Configuration supplying ``server_san_host`` and ``server_san_port``.

    Returns:
        A ``SubjectAlternativeName`` extension (IP or DNS, plus ``tcp://`` URI).
    """
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
    """
    Load the TLS server private key from disk, or generate a 2048-bit RSA key and save it.

    Args:
        cfg (LocalCaCfg): Local CA configuration.

    Returns:
        The server ``RSAPrivateKey``.
    """
    p = cfg.paths
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
    """
    Load or issue the TLS server certificate (SAN, serverAuth), signed by the CA.

    Args:
        server_key (rsa.RSAPrivateKey): Server key paired with the certificate.
        ca_key (rsa.RSAPrivateKey): CA private key.
        ca_cert (x509.Certificate): CA certificate (issuer).
        local_ca_cfg (LocalCaCfg): Validity and path configuration.

    Returns:
        The server ``Certificate`` (written to the configured server cert path).
    """
    p = local_ca_cfg.paths
    if p.server_cert_path.exists():
        return x509.load_pem_x509_certificate(p.server_cert_path.read_bytes())

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "robot-server")])

    san = _server_san_for_cfg(local_ca_cfg)

    with _CA_FILE_LOCK:
        serial = _next_serial_number(p)
        not_before = datetime.now(UTC)
        not_after = not_before + timedelta(days=local_ca_cfg.server_cert_validity_days)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        fname = f"{format(serial, 'X')}.pem"
        _append_index_line(
            p=p,
            status=CertStatus.Valid,
            not_after=cert.not_valid_after_utc,
            revoke_at=None,
            serial=serial,
            fname=fname,
            dn_openssl=_name_to_openssl_dn(subject),
        )
        _write_newcert_copy(p, serial, pem)
        p.server_cert_path.write_bytes(pem)
    return cert
