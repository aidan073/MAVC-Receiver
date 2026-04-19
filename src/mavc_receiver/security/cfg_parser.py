import yaml
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LocalCaPaths:
    ca_dir: Path
    certs_dir: Path
    private_dir: Path
    newcerts_dir: Path
    ca_key_path: Path
    ca_cert_path: Path
    server_key_path: Path
    server_cert_path: Path
    server_csr_path: Path
    index_path: Path
    serial_path: Path


@dataclass
class LocalCaCfg:
    ca_root: str = "ca"
    certs_subdir: str = "certs"
    private_subdir: str = "private"
    newcerts_subdir: str = "newcerts"
    ca_key_file: str = "ca.key.pem"
    ca_cert_file: str = "ca.cert.pem"
    server_key_file: str = "server.key.pem"
    server_cert_file: str = "server.cert.pem"
    server_csr_file: str = "server.csr.pem"
    index_file: str = "index.txt"
    serial_file: str = "serial"
    server_san_host: str = "127.0.0.1"
    server_san_port: int = 5073
    ca_validity_days: int = 3650
    server_cert_validity_days: int = 825
    client_cert_validity_days: int = 365


def resolve_local_ca_paths(cfg: LocalCaCfg) -> LocalCaPaths:
    ca = Path(cfg.ca_root)
    certs = ca / cfg.certs_subdir
    private = ca / cfg.private_subdir
    newcerts = ca / cfg.newcerts_subdir
    return LocalCaPaths(
        ca_dir=ca,
        certs_dir=certs,
        private_dir=private,
        newcerts_dir=newcerts,
        ca_key_path=private / cfg.ca_key_file,
        ca_cert_path=certs / cfg.ca_cert_file,
        server_key_path=private / cfg.server_key_file,
        server_cert_path=certs / cfg.server_cert_file,
        server_csr_path=ca / cfg.server_csr_file,
        index_path=ca / cfg.index_file,
        serial_path=ca / cfg.serial_file,
    )


def _set_defaults(raw: Any) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("[MAVC-Receiver] local CA config root must be a mapping")
    defaults = {f.name: getattr(LocalCaCfg(), f.name) for f in fields(LocalCaCfg)}
    merged = {**defaults, **raw}
    return merged


def load_local_ca_cfg(path: Path) -> LocalCaCfg:
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    complete = _set_defaults(raw)
    return LocalCaCfg(
        ca_root=str(complete["ca_root"]),
        certs_subdir=str(complete["certs_subdir"]),
        private_subdir=str(complete["private_subdir"]),
        newcerts_subdir=str(complete["newcerts_subdir"]),
        ca_key_file=str(complete["ca_key_file"]),
        ca_cert_file=str(complete["ca_cert_file"]),
        server_key_file=str(complete["server_key_file"]),
        server_cert_file=str(complete["server_cert_file"]),
        server_csr_file=str(complete["server_csr_file"]),
        index_file=str(complete["index_file"]),
        serial_file=str(complete["serial_file"]),
        server_san_host=str(complete["server_san_host"]),
        server_san_port=int(complete["server_san_port"]),
        ca_validity_days=int(complete["ca_validity_days"]),
        server_cert_validity_days=int(complete["server_cert_validity_days"]),
        client_cert_validity_days=int(complete["client_cert_validity_days"]),
    )
