from ..utils import ensure_dirs
from ...enum import CertStatus
from ..cfg_parser import LocalCaCfg
from .ca import (
    _CA_FILE_LOCK,
    _append_index_line,
    _name_to_openssl_dn,
    _next_serial_number,
    _write_newcert_copy,
)

from cryptography import x509
from datetime import UTC, datetime, timedelta
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization


def sign_client_csr(
    csr_pem: bytes,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    local_ca_cfg: LocalCaCfg,
) -> bytes:
    """
    Validate and sign a client CSR, append the index row, and store ``newcerts`` copy.

    Args:
        csr_pem (bytes): PEM-encoded certificate signing request.
        ca_key (rsa.RSAPrivateKey): CA private key.
        ca_cert (x509.Certificate): Issuing CA certificate.
        local_ca_cfg (LocalCaCfg): Client validity and paths.

    Returns:
        The issued certificate as PEM bytes.

    Raises:
        ValueError: If the CSR signature is invalid.
    """
    ensure_dirs(local_ca_cfg)
    p = local_ca_cfg.paths
    csr = x509.load_pem_x509_csr(csr_pem)

    if not csr.is_signature_valid:
        raise ValueError("[MAVC-Receiver] Invalid CSR signature")

    validity_days = local_ca_cfg.client_cert_validity_days

    with _CA_FILE_LOCK:
        serial = _next_serial_number(p)
        not_before = datetime.now(UTC)
        not_after = not_before + timedelta(days=validity_days)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
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
            dn_openssl=_name_to_openssl_dn(csr.subject),
        )
        _write_newcert_copy(p, serial, pem)
    return pem
