from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import LogConfig


def _rotate(path: Path, keep: int) -> None:
    """Rotate path → path.1 → path.2 … dropping the oldest."""
    for i in range(keep - 1, 0, -1):
        src = path.with_suffix(path.suffix + f".{i}")
        dst = path.with_suffix(path.suffix + f".{i + 1}")
        if src.exists():
            src.replace(dst)
    if path.exists():
        path.replace(path.with_suffix(path.suffix + ".1"))


def log(entry: dict[str, Any], cfg: LogConfig) -> None:
    """Append a JSON line. Rotate on size. Swallows its own errors — logging
    failure must never block a permission decision."""
    try:
        cfg.path.parent.mkdir(parents=True, exist_ok=True)
        if cfg.path.exists() and cfg.path.stat().st_size > cfg.rotate_mb * 1024 * 1024:
            _rotate(cfg.path, cfg.keep)
        with cfg.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":"), default=str) + "\n")
    except Exception:  # noqa: BLE001
        pass
