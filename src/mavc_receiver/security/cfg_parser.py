import yaml
from pathlib import Path

from typing import Any, ClassVar

_LOCAL_CA_DEFAULTS: dict[str, Any] = {
    "ca_root": "ca",
    "certs_subdir": "certs",
    "private_subdir": "private",
    "newcerts_subdir": "newcerts",
    "ca_key_file": "ca.key.pem",
    "ca_cert_file": "ca.cert.pem",
    "server_key_file": "server.key.pem",
    "server_cert_file": "server.cert.pem",
    "server_csr_file": "server.csr.pem",
    "index_file": "index.txt",
    "serial_file": "serial",
    "crl_file": "ca.crl.pem",
    "crl_next_update_hours": 24,
    "server_san_host": "127.0.0.1",
    "server_san_port": 5073,
    "ca_validity_days": 3650,
    "server_cert_validity_days": 825,
    "client_cert_validity_days": 365,
}


class LocalCaPaths:
    """Resolved filesystem paths for the local CA layout (singleton)."""

    _instance: ClassVar["LocalCaPaths | None"] = None

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
    crl_path: Path

    def __init__(self) -> None:
        raise RuntimeError(
            "[MAVC-Receiver] Do not directly instantiate LocalCaPaths. Instead, use LocalCaPaths.instance() after LocalCaCfg is loaded"
        )

    @classmethod
    def instance(cls) -> "LocalCaPaths":
        if cls._instance is None:
            raise RuntimeError(
                "[MAVC-Receiver] LocalCaPaths not initialized; load LocalCaCfg first"
            )
        return cls._instance

    @classmethod
    def _from_cfg(cls, cfg: "LocalCaCfg") -> "LocalCaPaths":
        if cls._instance is not None:
            return cls._instance
        ca = Path(cfg.ca_root)
        certs = ca / cfg.certs_subdir
        private = ca / cfg.private_subdir
        newcerts = ca / cfg.newcerts_subdir
        obj = object.__new__(cls)
        obj.ca_dir = ca
        obj.certs_dir = certs
        obj.private_dir = private
        obj.newcerts_dir = newcerts
        obj.ca_key_path = private / cfg.ca_key_file
        obj.ca_cert_path = certs / cfg.ca_cert_file
        obj.server_key_path = private / cfg.server_key_file
        obj.server_cert_path = certs / cfg.server_cert_file
        obj.server_csr_path = ca / cfg.server_csr_file
        obj.index_path = ca / cfg.index_file
        obj.serial_path = ca / cfg.serial_file
        obj.crl_path = certs / cfg.crl_file
        cls._instance = obj
        return obj


class LocalCaCfg:
    """YAML-backed local CA settings (singleton). Holds :class:`LocalCaPaths` via ``paths``."""

    _instance: ClassVar["LocalCaCfg | None"] = None

    ca_root: str
    certs_subdir: str
    private_subdir: str
    newcerts_subdir: str
    ca_key_file: str
    ca_cert_file: str
    server_key_file: str
    server_cert_file: str
    server_csr_file: str
    index_file: str
    serial_file: str
    crl_file: str
    crl_next_update_hours: int
    server_san_host: str
    server_san_port: int
    ca_validity_days: int
    server_cert_validity_days: int
    client_cert_validity_days: int

    def __init__(self) -> None:
        raise RuntimeError(
            "[MAVC-Receiver] Do not directly instantiate LocalCaCfg. Instead, use load_local_ca_cfg() to construct LocalCaCfg"
        )

    @classmethod
    def instance(cls) -> "LocalCaCfg":
        if cls._instance is None:
            raise RuntimeError(
                "[MAVC-Receiver] LocalCaCfg not loaded; call load_local_ca_cfg first"
            )
        return cls._instance

    @property
    def paths(self) -> LocalCaPaths:
        return self._paths

    @classmethod
    def _from_mapping(cls, raw: dict[str, Any]) -> "LocalCaCfg":
        if cls._instance is not None:
            return cls._instance
        obj = object.__new__(cls)
        obj.ca_root = str(raw["ca_root"])
        obj.certs_subdir = str(raw["certs_subdir"])
        obj.private_subdir = str(raw["private_subdir"])
        obj.newcerts_subdir = str(raw["newcerts_subdir"])
        obj.ca_key_file = str(raw["ca_key_file"])
        obj.ca_cert_file = str(raw["ca_cert_file"])
        obj.server_key_file = str(raw["server_key_file"])
        obj.server_cert_file = str(raw["server_cert_file"])
        obj.server_csr_file = str(raw["server_csr_file"])
        obj.index_file = str(raw["index_file"])
        obj.serial_file = str(raw["serial_file"])
        obj.crl_file = str(raw["crl_file"])
        obj.crl_next_update_hours = int(raw["crl_next_update_hours"])
        obj.server_san_host = str(raw["server_san_host"])
        obj.server_san_port = int(raw["server_san_port"])
        obj.ca_validity_days = int(raw["ca_validity_days"])
        obj.server_cert_validity_days = int(raw["server_cert_validity_days"])
        obj.client_cert_validity_days = int(raw["client_cert_validity_days"])
        obj._paths = LocalCaPaths._from_cfg(obj)
        cls._instance = obj
        return obj


def _set_defaults(raw: Any) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("[MAVC-Receiver] local CA config root must be a mapping")
    merged = {**_LOCAL_CA_DEFAULTS, **raw}
    return merged


def load_local_ca_cfg(path: Path) -> LocalCaCfg:
    """Parse YAML and return the :class:`LocalCaCfg` singleton (composed :class:`LocalCaPaths` is built once)."""
    if LocalCaCfg._instance is not None:
        return LocalCaCfg.instance()
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    complete = _set_defaults(raw)
    return LocalCaCfg._from_mapping(complete)


def _coerce_cfg(local_ca_cfg: Path | str | LocalCaCfg) -> LocalCaCfg:
    """Normalize a config argument to the loaded :class:`LocalCaCfg` singleton."""
    if isinstance(local_ca_cfg, (Path, str)):
        return load_local_ca_cfg(Path(local_ca_cfg))
    if not isinstance(local_ca_cfg, LocalCaCfg):
        raise ValueError(
            "[MAVC-Receiver] Expected a path to a local CA YAML file or LocalCaCfg, "
            f"not {type(local_ca_cfg)}."
        )
    return local_ca_cfg
