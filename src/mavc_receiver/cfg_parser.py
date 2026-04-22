import yaml
from dataclasses import dataclass, fields

from typing import Any
from pathlib import Path


@dataclass
class ReceiverCfg:
    buffer_size: int = 1024
    bind_host: str = "0.0.0.0"
    bind_port: int = 5073
    max_connections: int = 1
    verify_client_identity: bool = False
    server_cert_path: str | None = None
    server_key_path: str | None = None
    ca_cert_path: str | None = None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _set_defaults(raw: Any) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("[MAVC-Receiver] receiver config root must be a mapping")
    defaults = {f.name: getattr(ReceiverCfg(), f.name) for f in fields(ReceiverCfg)}
    merged = {**defaults, **raw}
    return merged


def validate_receiver_mtls_cfg(cfg: ReceiverCfg) -> None:
    """Require PEM paths and existing files when :attr:`ReceiverCfg.verify_client_identity` is True."""
    if not cfg.verify_client_identity:
        return
    checks = (
        ("server_cert_path", cfg.server_cert_path),
        ("server_key_path", cfg.server_key_path),
        ("ca_cert_path", cfg.ca_cert_path),
    )
    # Check if necessary cfg values are missing
    missing_val = [name for name, val in checks if not val]
    if missing_val:
        raise ValueError(
            "[MAVC-Receiver] When verify_client_identity is True, "
            + ", ".join(missing_val)
            + " must be set to existing PEM file paths."
        )
    # Check if necessary cfg paths are invalid
    missing_path = [name for name, path in checks if not Path(path).is_file()]
    if missing_path:
        raise ValueError(
            "[MAVC-Receiver] The following PEM file paths were invalid: "
            + ", ".join(missing_path)
        )


def load_cfg(path: Path) -> ReceiverCfg:
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    complete = _set_defaults(raw)
    cfg = ReceiverCfg(
        buffer_size=int(complete["buffer_size"]),
        bind_host=str(complete["bind_host"]),
        bind_port=int(complete["bind_port"]),
        max_connections=int(complete["max_connections"]),
        verify_client_identity=bool(complete["verify_client_identity"]),
        server_cert_path=_optional_str(complete.get("server_cert_path")),
        server_key_path=_optional_str(complete.get("server_key_path")),
        ca_cert_path=_optional_str(complete.get("ca_cert_path")),
    )
    validate_receiver_mtls_cfg(cfg)
    return cfg
