"""env_loader.py
Minimal .env loader with no external dependencies.
"""
from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | None = None) -> dict[str, str]:
    """Load KEY=VALUE pairs from a local .env file into os.environ.

    Rules:
    - ignores blank lines and comments
    - supports optional leading `export `
    - does not override existing environment variables
    """
    env_path = Path(path or ".env")
    loaded: dict[str, str] = {}

    if not env_path.exists():
        return loaded

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        loaded[key] = value
        os.environ.setdefault(key, value)

    return loaded
