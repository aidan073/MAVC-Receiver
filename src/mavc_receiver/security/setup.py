from .cfg_parser import LocalCaCfg, _coerce_cfg
from .core.crl import revoke_certificate, write_crl
from .core.server import create_server_cert, load_or_create_server_key
from .core.ca import (
    create_ca_cert,
    ensure_dirs,
    load_or_create_ca_key,
)

from pathlib import Path


def setup_ca_system(local_ca_cfg: Path | str | LocalCaCfg) -> None:
    """
    Creates CA, server keys/certs, and empty CRL if they don't already exist, at the paths specified
    in the config file (or defaults). Each of them that already exist will remain unchanged.

    Args:
        local_ca_cfg (Path | str | LocalCaCfg): Path to YAML, or loaded ``LocalCaCfg``.
    """
    cfg = _coerce_cfg(local_ca_cfg)

    ensure_dirs(cfg)
    paths = cfg.paths

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
