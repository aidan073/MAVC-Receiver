from .utils import ensure_dirs
from .cfg_parser import LocalCaCfg, _coerce_cfg
from .core.crl import revoke_certificate, write_crl
from .core.ca import (
    create_ca_cert,
    create_ca_key,
    load_ca_cert,
    load_ca_key,
)
from .core.client import sign_client_csr
from .core.server import (
    create_server_cert,
    create_server_key,
    load_server_cert,
    load_server_key,
)

from pathlib import Path


def _missing_ca_message(cfg: LocalCaCfg) -> str:
    p = cfg.paths
    return (
        f"[MAVC-Receiver] CA key or certificate not found "
        f"({p.ca_key_path} / {p.ca_cert_path}); run setup_ca first."
    )


def setup_ca(
    local_ca_cfg: Path | str | LocalCaCfg,
    *,
    quiet: bool = False,
) -> None:
    """
    Ensure CA directories exist, create the CA key and self-signed CA certificate if missing.

    Args:
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.
        quiet: If True, skip status prints (for use inside ``full_setup``).
    """
    cfg = _coerce_cfg(local_ca_cfg)
    ensure_dirs(cfg)
    paths = cfg.paths

    ca_key = load_ca_key(cfg)
    if ca_key is None:
        ca_key = create_ca_key(cfg)

    if load_ca_cert(cfg) is None:
        create_ca_cert(ca_key, cfg)

    if not quiet:
        print("[MAVC-Receiver] CA certificate ready.")
        print(f"CA cert: {paths.ca_cert_path}")


def setup_server(
    local_ca_cfg: Path | str | LocalCaCfg,
    *,
    quiet: bool = False,
) -> None:
    """
    Create the TLS server key (if missing) and server certificate, signed by the existing CA.

    Requires the CA key and CA certificate to already exist.

    Args:
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.
        quiet: If True, skip status prints (for use inside ``full_setup``).
    """
    cfg = _coerce_cfg(local_ca_cfg)
    ensure_dirs(cfg)
    paths = cfg.paths

    ca_key = load_ca_key(cfg)
    ca_cert = load_ca_cert(cfg)
    if ca_key is None or ca_cert is None:
        raise RuntimeError(_missing_ca_message(cfg))

    server_key = load_server_key(cfg)
    if server_key is None:
        server_key = create_server_key(cfg)

    if load_server_cert(cfg) is None:
        create_server_cert(server_key, ca_key, ca_cert, local_ca_cfg=cfg)

    if not quiet:
        print("[MAVC-Receiver] Server certificate ready.")
        print(f"Server cert: {paths.server_cert_path}")


def setup_client(
    local_ca_cfg: Path | str | LocalCaCfg,
    csr_path: Path,
    cert_out_path: Path,
    *,
    quiet: bool = False,
) -> None:
    """
    Sign a client CSR and write the issued certificate PEM. Requires an existing CA.

    Args:
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.
        csr_path: Path to the client's PEM CSR.
        cert_out_path: Path to write the issued client certificate PEM.
        quiet: If True, skip status prints (for use inside ``full_setup``).
    """
    cfg = _coerce_cfg(local_ca_cfg)
    if not csr_path.is_file():
        raise FileNotFoundError(f"[MAVC-Receiver] CSR not found: {csr_path}")

    ca_key = load_ca_key(cfg)
    ca_cert = load_ca_cert(cfg)
    if ca_key is None or ca_cert is None:
        raise RuntimeError(_missing_ca_message(cfg))

    ensure_dirs(cfg)
    csr_pem = csr_path.read_bytes()
    pem = sign_client_csr(csr_pem, ca_key, ca_cert, cfg)
    cert_out_path.parent.mkdir(parents=True, exist_ok=True)
    cert_out_path.write_bytes(pem)
    if not quiet:
        print(f"[MAVC-Receiver] Issued client certificate written to {cert_out_path}")


def setup_crl(
    local_ca_cfg: Path | str | LocalCaCfg,
    *,
    quiet: bool = False,
) -> Path:
    """
    Build the CRL from ``index.txt`` and write it to the configured path (requires existing CA).

    Args:
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.
        quiet: If True, skip status prints (for use inside ``full_setup``).

    Returns:
        Path to the written CRL PEM.
    """
    cfg = _coerce_cfg(local_ca_cfg)
    out = write_crl(cfg)
    if not quiet:
        print("[MAVC-Receiver] CRL written.")
        print(f"CRL: {out}")
    return out


def export_ca_cert_to_path(
    local_ca_cfg: Path | str | LocalCaCfg,
    out_path: Path,
    *,
    quiet: bool = False,
) -> None:
    """Copy the CA certificate PEM to ``out_path`` (e.g. a USB drive for trust store setup)."""
    cfg = _coerce_cfg(local_ca_cfg)
    src = cfg.paths.ca_cert_path
    if not src.is_file():
        raise FileNotFoundError(
            f"[MAVC-Receiver] CA certificate not found at {src}; run setup_ca first."
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(src.read_bytes())
    if not quiet:
        print(f"[MAVC-Receiver] CA certificate copied to {out_path}")


def full_setup(
    local_ca_cfg: Path | str | LocalCaCfg,
    *,
    csr_path: Path,
    cert_out_path: Path,
    export_ca_path: Path,
    quiet: bool = False,
) -> None:
    """
    Run ``setup_ca``, ``setup_server``, ``setup_client``, ``setup_crl``, and
    ``export_ca_cert_to_path`` in order.

    Args:
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.
        csr_path: Path to the client's PEM CSR to sign.
        cert_out_path: Path to write the issued client certificate PEM.
        export_ca_path: Destination path for copying the CA certificate PEM.
        quiet: If True, skip the final summary prints.
    """
    cfg = _coerce_cfg(local_ca_cfg)
    setup_ca(local_ca_cfg, quiet=True)
    setup_server(local_ca_cfg, quiet=True)
    setup_client(
        local_ca_cfg,
        csr_path,
        cert_out_path,
        quiet=True,
    )
    setup_crl(local_ca_cfg, quiet=True)
    export_ca_cert_to_path(local_ca_cfg, export_ca_path, quiet=True)
    if not quiet:
        paths = cfg.paths
        print("[MAVC-Receiver] Full setup complete.")
        print(f"CA cert: {paths.ca_cert_path}")
        print(f"Server cert: {paths.server_cert_path}")
        print(f"Client cert: {cert_out_path}")
        print(f"CRL: {paths.crl_path}")
        print(f"CA cert exported to: {export_ca_path}")


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
        required=True,
        help="Setup step, full setup, or revocation (see subcommand help).",
    )
    sub.add_parser(
        "setup-crl",
        help="Rebuild the CRL from revoked rows in index.txt (refresh nextUpdate).",
    )
    sub.add_parser(
        "crl",
        help="Alias for setup-crl.",
    )
    p_revoke = sub.add_parser(
        "revoke",
        help="Revoke a certificate by serial and rewrite the CRL.",
    )
    p_revoke.add_argument(
        "serial",
        help="Certificate serial: decimal or hex (e.g. 4096 or 0x1000).",
    )
    sub.add_parser(
        "setup-ca",
        help="Create CA key and CA certificate only (if not already present).",
    )
    sub.add_parser(
        "setup-server",
        help="Create server key and certificate (requires existing CA).",
    )
    p_client = sub.add_parser(
        "setup-client",
        help=(
            "Sign a client CSR PEM from a path and write the issued certificate "
            "(requires existing CA)."
        ),
    )
    p_client.add_argument(
        "--csr",
        type=Path,
        required=True,
        help="Path to the client's PEM CSR (e.g. on a removable drive).",
    )
    p_client.add_argument(
        "--cert-out",
        type=Path,
        required=True,
        help="Path to write the issued client certificate PEM.",
    )
    p_export_ca = sub.add_parser(
        "export-ca",
        help="Copy the CA certificate PEM to a path (e.g. USB for installing the trust anchor).",
    )
    p_export_ca.add_argument(
        "--out",
        type=Path,
        required=True,
        dest="ca_out",
        help="Destination file path for the CA certificate PEM.",
    )
    p_full = sub.add_parser(
        "full-setup",
        help=(
            "Run setup-ca, setup-server, setup-client, setup-crl, and export-ca in one step."
        ),
    )
    p_full.add_argument(
        "--csr",
        type=Path,
        required=True,
        help="Path to the client's PEM CSR to sign.",
    )
    p_full.add_argument(
        "--cert-out",
        type=Path,
        required=True,
        help="Path to write the issued client certificate PEM.",
    )
    p_full.add_argument(
        "--export-ca-out",
        type=Path,
        required=True,
        help="Where to copy the CA certificate PEM (e.g. USB path).",
    )

    args = parser.parse_args()

    if args.command in ("setup-crl", "crl"):
        setup_crl(args.config)
    elif args.command == "revoke":
        out = revoke_certificate(args.serial, local_ca_cfg=args.config)
        print(f"Revoked; CRL written to {out}")
    elif args.command == "setup-ca":
        setup_ca(args.config)
    elif args.command == "setup-server":
        setup_server(args.config)
    elif args.command == "setup-client":
        setup_client(
            args.config,
            csr_path=args.csr,
            cert_out_path=args.cert_out,
        )
    elif args.command == "export-ca":
        export_ca_cert_to_path(args.config, out_path=args.ca_out)
    elif args.command == "full-setup":
        full_setup(
            args.config,
            csr_path=args.csr,
            cert_out_path=args.cert_out,
            export_ca_path=args.export_ca_out,
        )
    else:
        raise AssertionError(f"unexpected command: {args.command!r}")


if __name__ == "__main__":
    main()
