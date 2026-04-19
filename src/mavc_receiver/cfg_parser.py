import yaml
from dataclasses import dataclass, fields

from typing import Any
from pathlib import Path


@dataclass
class ReceiverCfg:
    message_size: int = 128
    buffer_size: int = 1024
    bind_host: str = "0.0.0.0"
    bind_port: int = 5073
    max_connections: int = 1


def _set_defaults(raw: Any) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("[MAVC-Receiver] receiver config root must be a mapping")
    defaults = {f.name: getattr(ReceiverCfg(), f.name) for f in fields(ReceiverCfg)}
    merged = {**defaults, **raw}
    return merged


def load_cfg(path: Path) -> ReceiverCfg:
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    complete = _set_defaults(raw)
    return ReceiverCfg(
        message_size=int(complete["message_size"]),
        buffer_size=int(complete["buffer_size"]),
        bind_host=str(complete["bind_host"]),
        bind_port=int(complete["bind_port"]),
        max_connections=int(complete["max_connections"]),
    )
