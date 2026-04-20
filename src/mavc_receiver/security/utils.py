from .cfg_parser import LocalCaCfg


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
