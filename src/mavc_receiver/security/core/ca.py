from ...enum import CertStatus
from ..cfg_parser import LocalCaCfg, LocalCaPaths

import os
import threading
from pathlib import Path
from cryptography import x509
from dataclasses import dataclass
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

# Lock on CA index file
_CA_FILE_LOCK = threading.Lock()


@dataclass(frozen=True)
class CaIndexEntry:
    """One row of the OpenSSL-style CA index."""

    status: str
    expiry: str
    revocation: str
    serial_hex: str
    filename: str
    dn_openssl: str

    def __str__(self) -> str:
        return (
            f"{self.status}\t{self.expiry}\t{self.revocation}\t"
            f"{self.serial_hex}\t{self.filename}\t{self.dn_openssl}\n"
        )


def _parse_index_line(line: str) -> CaIndexEntry | None:
    """
    Convert a single ``index.txt`` line to a ``CaIndexEntry``, or skip unparseable lines.

    Args:
        line (str): One line from the CA index file (may include trailing newline).

    Returns:
        The parsed ``CaIndexEntry``, or ``None`` if the line is blank, a comment,
        or has fewer than six tab-separated fields.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split("\t")
    if len(parts) < 6:
        return None
    status, exp, rev, ser_hex, fname = (
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        parts[4],
    )
    dn = "\t".join(parts[5:])
    return CaIndexEntry(
        status=status,
        expiry=exp,
        revocation=rev,
        serial_hex=ser_hex,
        filename=fname,
        dn_openssl=dn,
    )


class DateFormatter:
    """Convert between UTC datetimes and OpenSSL ``index.txt`` date strings."""

    @staticmethod
    def _to_string(dt: datetime) -> str:
        return dt.strftime("%y%m%d%H%M%SZ")

    @staticmethod
    def _to_date(s: str) -> datetime:
        return datetime.strptime(s, "%y%m%d%H%M%SZ")


_OID_SHORT: dict[object, str] = {
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COMMON_NAME: "CN",
    NameOID.EMAIL_ADDRESS: "emailAddress",
}


def _name_to_openssl_dn(name: x509.Name) -> str:
    """
    Build an OpenSSL-style distinguished name string from an X.509 ``Name``.

    Args:
        name (x509.Name): Certificate or CSR subject/issuer name.

    Returns:
        A ``/C=.../CN=...`` style string suitable for the CA index ``DN`` field.
    """
    parts: list[str] = []
    for attr in name:
        short = _OID_SHORT.get(attr.oid)
        if short is None:
            short = attr.oid.dotted_string
        parts.append(f"{short}={attr.value}")
    return "/" + "/".join(parts)


def _next_serial_number(p: LocalCaPaths) -> int:
    """
    Read the current hex serial, increment it on disk, and return the value used.

    Args:
        p (LocalCaPaths): Resolved paths for the local CA layout.

    Returns:
        The serial number (integer) prior to incrementing.
    """
    text = p.serial_path.read_text(encoding="ascii").strip()
    n = int(text, 16)
    p.serial_path.write_text(f"{format(n + 1, 'X')}\n", encoding="ascii")
    return n


def _append_index_line(
    p: LocalCaPaths,
    status: CertStatus,
    not_after: datetime,
    revoke_at: datetime | None,
    serial: int,
    fname: str,
    dn_openssl: str,
) -> None:
    """
    Append one row to the CA ``index.txt`` for a newly issued certificate.

    Args:
        p (LocalCaPaths): Resolved paths for the local CA layout.
        status (CertStatus): Index status (typically ``Valid`` for new certs).
        not_after (datetime): Certificate ``notAfter`` time.
        revoke_at (datetime | None): Revocation time, or ``None`` if not revoked.
        serial (int): Certificate serial number.
        fname (str): Basename of the PEM file under ``newcerts`` (e.g. ``1000.pem``).
        dn_openssl (str): OpenSSL-style DN string for the subject.
    """
    revocation = "" if revoke_at is None else DateFormatter._to_string(revoke_at)
    entry = CaIndexEntry(
        status=status.value,
        expiry=DateFormatter._to_string(not_after),
        revocation=revocation,
        serial_hex=format(serial, "X"),
        filename=fname,
        dn_openssl=dn_openssl,
    )
    with p.index_path.open("a", encoding="ascii") as f:
        f.write(str(entry))


def _write_newcert_copy(p: LocalCaPaths, serial: int, pem: bytes) -> None:
    """
    Store a PEM-encoded certificate under ``newcerts/{serial}.pem``.

    Args:
        p (LocalCaPaths): Resolved paths for the local CA layout.
        serial (int): Certificate serial number (hex basename).
        pem (bytes): DER-wrapped PEM bytes to write.
    """
    name = f"{format(serial, 'X')}.pem"
    (p.newcerts_dir / name).write_bytes(pem)


def _parse_index_rows(text: str) -> list[CaIndexEntry]:
    """
    Parse all index rows from the full contents of ``index.txt``.

    Args:
        text (str): Raw file text (UTF-8 decoded).

    Returns:
        A list of ``CaIndexEntry`` for each parseable line; blanks and comments are skipped.
    """
    rows: list[CaIndexEntry] = []
    for raw in text.splitlines():
        entry = _parse_index_line(raw)
        if entry is not None:
            rows.append(entry)
    return rows


# ===== Helpers =====
def ensure_dirs(cfg: LocalCaCfg) -> None:
    """
    Create CA directories, touch ``index.txt``, and initialize ``serial`` if missing.

    Args:
        cfg (LocalCaCfg): Local CA configuration.
    """
    p = cfg.paths
    p.certs_dir.mkdir(parents=True, exist_ok=True)
    p.private_dir.mkdir(parents=True, exist_ok=True)
    p.newcerts_dir.mkdir(parents=True, exist_ok=True)

    p.index_path.touch(exist_ok=True)
    if not p.serial_path.exists():
        p.serial_path.write_text("1000\n")


def save_private_key(key: rsa.RSAPrivateKey, path: Path):
    """
    Write an RSA private key to PEM (traditional OpenSSL, no encryption) with ``0600`` perms.

    Args:
        key (rsa.RSAPrivateKey): Key material to persist.
        path (Path): Destination file path.
    """
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    os.chmod(path, 0o600)


def load_or_create_ca_key(cfg: LocalCaCfg) -> rsa.RSAPrivateKey:
    """
    Load the CA private key from disk, or generate a 4096-bit RSA key and save it.

    Args:
        cfg (LocalCaCfg): Local CA configuration.

    Returns:
        The CA ``RSAPrivateKey``.
    """
    p = cfg.paths
    if p.ca_key_path.exists():
        return serialization.load_pem_private_key(
            p.ca_key_path.read_bytes(),
            password=None,
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    save_private_key(key, p.ca_key_path)
    return key


def create_ca_cert(ca_key: rsa.RSAPrivateKey, cfg: LocalCaCfg) -> x509.Certificate:
    """
    Load or create the self-signed CA certificate, updating the index and ``newcerts``.

    Args:
        ca_key (rsa.RSAPrivateKey): CA signing key.
        cfg (LocalCaCfg): Local CA configuration (validity, paths).

    Returns:
        The CA ``Certificate`` (PEM on disk at the configured path).
    """
    p = cfg.paths
    if p.ca_cert_path.exists():
        return x509.load_pem_x509_certificate(p.ca_cert_path.read_bytes())

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Robot-Local-CA")]
    )

    with _CA_FILE_LOCK:
        serial = _next_serial_number(p)
        not_before = datetime.now(UTC)
        not_after = not_before + timedelta(days=cfg.ca_validity_days)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
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
        p.ca_cert_path.write_bytes(pem)
    return cert
