from ...enum import CertStatus
from ..cfg_parser import LocalCaCfg, _coerce_cfg
from .ca import (
    CaIndexEntry,
    DateFormatter,
    _CA_FILE_LOCK,
    ensure_dirs,
    _parse_index_line,
    _parse_index_rows,
)

import re
from pathlib import Path
from cryptography import x509
from datetime import UTC, datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

import typing


def _normalize_serial_arg(serial: int | str) -> int:
    if isinstance(serial, int):
        return serial
    s = serial.strip().lower().replace("0x", "")
    if re.fullmatch(r"[0-9a-f]+", s):
        return int(s, 16)
    return int(s, 10)


def _iter_revoked_from_index(index_path: Path) -> list[tuple[int, datetime]]:
    """
    Collect revoked serial numbers and revocation datetimes from the index file.

    Args:
        index_path (Path): Path to ``index.txt``.

    Returns:
        Pairs ``(serial_int, revocation_datetime)`` for rows with status revoked
        and a non-empty revocation time. Empty if the file is missing.
    """
    out: list[tuple[int, datetime]] = []
    if not index_path.exists():
        return out
    for row in _parse_index_rows(index_path.read_text(encoding="utf-8")):
        if row.status != CertStatus.Revoked.value or not row.revocation:
            continue
        out.append((int(row.serial_hex, 16), DateFormatter._to_date(row.revocation)))
    return out


def _build_crl_pem(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    revoked: list[tuple[int, datetime]],
    next_update: timedelta,
) -> bytes:
    """
    Sign a PEM-encoded CRL listing the given revoked certificates.

    Args:
        ca_cert (x509.Certificate): Issuing CA certificate (CRL issuer).
        ca_key (rsa.RSAPrivateKey): CA private key for signing.
        revoked (list[tuple[int, datetime]]): Revoked serials and revocation times.
        next_update (timedelta): Interval from ``now`` for CRL ``nextUpdate``.

    Returns:
        CRL bytes in PEM encoding.
    """
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


def write_crl(local_ca_cfg: Path | str | LocalCaCfg) -> Path:
    """
    Build a CRL from revoked rows in ``index.txt`` and write it to the configured path.

    Args:
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.

    Returns:
        Path to the written CRL (PEM).
    """
    cfg = _coerce_cfg(local_ca_cfg)
    ensure_dirs(cfg)
    p = cfg.paths
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
    local_ca_cfg: Path | str | LocalCaCfg,
    revoked_at: datetime | None = None,
) -> Path:
    """
    Mark a certificate as revoked in ``index.txt`` and rewrite the CRL.

    Args:
        serial (int | str): Certificate serial (hex or decimal).
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.
        revoked_at (datetime | None): Revocation time; defaults to now (UTC).

    Returns:
        Path to the updated CRL after ``write_crl``.

    Raises:
        ValueError: If the serial is not found, already revoked, or not revokable.
    """
    cfg = _coerce_cfg(local_ca_cfg)
    ensure_dirs(cfg)
    p = cfg.paths
    target = _normalize_serial_arg(serial)
    when = revoked_at if revoked_at is not None else datetime.now(UTC)

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
            entry = _parse_index_line(line)
            if entry is None:
                new_lines.append(line)
                continue
            try:
                row_serial = int(entry.serial_hex, 16)
            except ValueError:
                new_lines.append(line)
                continue
            if row_serial != target:
                new_lines.append(line)
                continue
            if entry.status == CertStatus.Revoked.value:
                raise ValueError(
                    f"[MAVC-Receiver] Certificate already revoked (serial {entry.serial_hex})"
                )
            if entry.status != CertStatus.Valid.value:
                raise ValueError(
                    f"[MAVC-Receiver] Cannot revoke entry with status {entry.status!r} "
                    f"(serial {entry.serial_hex})"
                )
            rev_str = DateFormatter._to_string(when)
            new_lines.append(
                str(
                    CaIndexEntry(
                        status=CertStatus.Revoked.value,
                        expiry=entry.expiry,
                        revocation=rev_str,
                        serial_hex=entry.serial_hex,
                        filename=entry.filename,
                        dn_openssl=entry.dn_openssl,
                    )
                )
            )
            found = True
        if not found:
            raise ValueError(
                f"[MAVC-Receiver] No valid certificate with serial {target!r} in index"
            )
        p.index_path.write_text("".join(new_lines), encoding="utf-8")

    return write_crl(cfg)
