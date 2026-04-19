from .cfg_parser import (
    LocalCaCfg,
    LocalCaPaths,
    load_local_ca_cfg,
    resolve_local_ca_paths,
)

import os
import ipaddress
import re
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import typing

# OpenSSL-style index (tab-separated): status, expiry, revoke?, serial(hex), file, DN
_CA_FILE_LOCK = threading.Lock()

_OID_SHORT: dict[object, str] = {
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COMMON_NAME: "CN",
    NameOID.EMAIL_ADDRESS: "emailAddress",
}


def _openssl_index_time(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.strftime("%y%m%d%H%M%SZ")


def _parse_openssl_index_time(s: str) -> datetime:
    return datetime.strptime(s, "%y%m%d%H%M%SZ").replace(tzinfo=UTC)


def _name_to_openssl_dn(name: x509.Name) -> str:
    parts: list[str] = []
    for attr in name:
        short = _OID_SHORT.get(attr.oid)
        if short is None:
            short = attr.oid.dotted_string
        parts.append(f"{short}={attr.value}")
    return "/" + "/".join(parts)


def _cert_not_after_for_index(cert: x509.Certificate) -> datetime:
    return cert.not_valid_after_utc


def _next_serial_number(p: LocalCaPaths) -> int:
    text = p.serial_path.read_text(encoding="ascii").strip()
    n = int(text, 16)
    p.serial_path.write_text(f"{format(n + 1, 'X')}\n", encoding="ascii")
    return n


def _append_index_line(
    p: LocalCaPaths,
    status: str,
    not_after: datetime,
    revoke_at: datetime | None,
    serial: int,
    fname: str,
    dn_openssl: str,
) -> None:
    exp = _openssl_index_time(not_after)
    rev = "" if revoke_at is None else _openssl_index_time(revoke_at)
    ser_hex = format(serial, "X")
    line = f"{status}\t{exp}\t{rev}\t{ser_hex}\t{fname}\t{dn_openssl}\n"
    with p.index_path.open("a", encoding="ascii") as f:
        f.write(line)


def _write_newcert_copy(p: LocalCaPaths, serial: int, pem: bytes) -> None:
    name = f"{format(serial, 'X')}.pem"
    (p.newcerts_dir / name).write_bytes(pem)


def _normalize_serial_arg(serial: int | str) -> int:
    if isinstance(serial, int):
        return serial
    s = serial.strip().lower().replace("0x", "")
    if re.fullmatch(r"[0-9a-f]+", s):
        return int(s, 16)
    return int(s, 10)


def _parse_index_rows(text: str) -> list[tuple[str, str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        status, exp, rev, ser_hex, fname = (
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            parts[4],
        )
        dn = "\t".join(parts[5:])
        rows.append((status, exp, rev, ser_hex, fname, dn))
    return rows


def _iter_revoked_from_index(index_path: Path) -> list[tuple[int, datetime]]:
    out: list[tuple[int, datetime]] = []
    if not index_path.exists():
        return out
    for status, _exp, rev, ser_hex, _fname, _dn in _parse_index_rows(
        index_path.read_text(encoding="utf-8")
    ):
        if status != "R" or not rev:
            continue
        out.append((int(ser_hex, 16), _parse_openssl_index_time(rev)))
    return out


def _build_crl_pem(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    revoked: list[tuple[int, datetime]],
    next_update: timedelta,
) -> bytes:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + next_update)
    )
    for serial, rev_date in revoked:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_date)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _coerce_local_ca_cfg(local_ca_cfg: Path | str | LocalCaCfg) -> LocalCaCfg:
    if isinstance(local_ca_cfg, (Path, str)):
        return load_local_ca_cfg(Path(local_ca_cfg))
    if not isinstance(local_ca_cfg, LocalCaCfg):
        raise ValueError(
            "[MAVC-Receiver] Expected a path to a local CA YAML file or LocalCaCfg, "
            f"not {type(local_ca_cfg)}."
        )
    return local_ca_cfg


# ===== Helpers =====
def ensure_dirs(cfg: LocalCaCfg) -> None:
    p = resolve_local_ca_paths(cfg)
    p.certs_dir.mkdir(parents=True, exist_ok=True)
    p.private_dir.mkdir(parents=True, exist_ok=True)
    p.newcerts_dir.mkdir(parents=True, exist_ok=True)

    p.index_path.touch(exist_ok=True)
    if not p.serial_path.exists():
        p.serial_path.write_text("1000\n")


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
            p,
            "V",
            _cert_not_after_for_index(cert),
            None,
            serial,
            fname,
            _name_to_openssl_dn(subject),
        )
        _write_newcert_copy(p, serial, pem)
        p.ca_cert_path.write_bytes(pem)
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
            p,
            "V",
            _cert_not_after_for_index(cert),
            None,
            serial,
            fname,
            _name_to_openssl_dn(subject),
        )
        _write_newcert_copy(p, serial, pem)
        p.server_cert_path.write_bytes(pem)
    return cert


def sign_client_csr(
    csr_pem: bytes,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    local_ca_cfg: LocalCaCfg,
) -> bytes:
    ensure_dirs(local_ca_cfg)
    p = resolve_local_ca_paths(local_ca_cfg)
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
            p,
            "V",
            _cert_not_after_for_index(cert),
            None,
            serial,
            fname,
            _name_to_openssl_dn(csr.subject),
        )
        _write_newcert_copy(p, serial, pem)
    return pem


def write_crl(local_ca_cfg: Path | str | LocalCaCfg) -> Path:
    """Build a CRL from revoked rows in ``index.txt`` and write it to the configured path."""
    cfg = _coerce_local_ca_cfg(local_ca_cfg)
    ensure_dirs(cfg)
    p = resolve_local_ca_paths(cfg)
    ca_key = typing.cast(
        rsa.RSAPrivateKey,
        serialization.load_pem_private_key(p.ca_key_path.read_bytes(), password=None),
    )
    ca_cert = x509.load_pem_x509_certificate(p.ca_cert_path.read_bytes())
    revoked = _iter_revoked_from_index(p.index_path)
    delta = timedelta(hours=cfg.crl_next_update_hours)
    pem = _build_crl_pem(ca_cert, ca_key, revoked, delta)
    p.crl_path.write_bytes(pem)
    return p.crl_path


def revoke_certificate(
    serial: int | str,
    *,
    local_ca_cfg: Path | str | LocalCaCfg,
    revoked_at: datetime | None = None,
) -> Path:
    """Mark a certificate as revoked in ``index.txt`` (``V`` → ``R``) and refresh the CRL."""
    cfg = _coerce_local_ca_cfg(local_ca_cfg)
    ensure_dirs(cfg)
    p = resolve_local_ca_paths(cfg)
    target = _normalize_serial_arg(serial)
    when = revoked_at if revoked_at is not None else datetime.now(UTC)
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)

    with _CA_FILE_LOCK:
        text = p.index_path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        new_lines: list[str] = []
        found = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                new_lines.append(line)
                continue
            parts = stripped.split("\t")
            if len(parts) < 6:
                new_lines.append(line)
                continue
            status, exp, rev, ser_hex, fname = (
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                parts[4],
            )
            dn = "\t".join(parts[5:])
            try:
                row_serial = int(ser_hex, 16)
            except ValueError:
                new_lines.append(line)
                continue
            if row_serial != target:
                new_lines.append(line)
                continue
            if status == "R":
                raise ValueError(
                    f"[MAVC-Receiver] Certificate already revoked (serial {ser_hex})"
                )
            if status != "V":
                raise ValueError(
                    f"[MAVC-Receiver] Cannot revoke entry with status {status!r} "
                    f"(serial {ser_hex})"
                )
            rev_str = _openssl_index_time(when)
            new_lines.append(f"R\t{exp}\t{rev_str}\t{ser_hex}\t{fname}\t{dn}\n")
            found = True
        if not found:
            raise ValueError(
                f"[MAVC-Receiver] No valid certificate with serial {target!r} in index"
            )
        p.index_path.write_text("".join(new_lines), encoding="utf-8")

    return write_crl(cfg)


# ===== Main setup =====
def setup_ca_system(local_ca_cfg: Path | str | LocalCaCfg):
    cfg = _coerce_local_ca_cfg(local_ca_cfg)

    ensure_dirs(cfg)
    paths = resolve_local_ca_paths(cfg)

    ca_key = load_or_create_ca_key(cfg)
    ca_cert = create_ca_cert(ca_key, cfg)

    server_key = load_or_create_server_key(cfg)
    create_server_cert(server_key, ca_key, ca_cert, local_ca_cfg=cfg)

    crl_path = write_crl(cfg)

    print("CA and server certificates ready.")
    print(f"CA cert: {paths.ca_cert_path}")
    print(f"Server cert: {paths.server_cert_path}")
    print(f"CRL: {crl_path}")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Generate and manage a local CA, TLS server certificate, and CRL "
            "(see cfg_examples/local_ca_cfg.yaml)."
        )
    )
    parser.add_argument(
        "config",
        type=Path,
        help="Path to the local CA YAML configuration file.",
    )
    sub = parser.add_subparsers(
        dest="command",
        metavar="command",
        required=False,
        help="Omit to create or refresh CA + server certs and write a CRL.",
    )
    sub.add_parser(
        "crl",
        help="Rebuild the CRL from revoked rows in index.txt (refresh nextUpdate).",
    )
    p_revoke = sub.add_parser(
        "revoke",
        help="Revoke a certificate by serial and rewrite the CRL.",
    )
    p_revoke.add_argument(
        "serial",
        help="Certificate serial: decimal or hex (e.g. 4096 or 0x1000).",
    )

    args = parser.parse_args()

    if args.command is None:
        setup_ca_system(args.config)
    elif args.command == "crl":
        out = write_crl(args.config)
        print(f"CRL written to {out}")
    elif args.command == "revoke":
        out = revoke_certificate(args.serial, local_ca_cfg=args.config)
        print(f"Revoked; CRL written to {out}")
    else:
        raise AssertionError(f"unexpected command: {args.command!r}")


if __name__ == "__main__":
    main()

