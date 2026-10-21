"""Disk cache used to avoid repeated advisory and lifecycle requests."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("kuvuln.cache")


def default_cache_dir() -> Path:
    explicit = os.getenv("KUVULN_CACHE_DIR")
    if explicit:
        return Path(explicit)
    base = os.getenv("XDG_CACHE_HOME")
    if base:
        return Path(base) / "kuvuln"
    return Path.home() / ".cache" / "kuvuln"


class Cache:
    def __init__(self, directory: str | Path | None = None) -> None:
        self.directory = Path(directory) if directory else default_cache_dir()
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            LOGGER.debug("Cache directory is not writable: %s", self.directory)

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.json"

    def get(
        self,
        key: str,
        ttl_hours: float | None = 24.0,
        allow_stale: bool = False,
    ) -> Any | None:
        path = self._path(key)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                entry = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        stored_at = float(entry.get("stored_at", 0))
        if (
            ttl_hours is not None
            and not allow_stale
            and time.time() - stored_at > ttl_hours * 3600
        ):
            return None
        return entry.get("value")

    def set(self, key: str, value: Any) -> None:
        path = self._path(key)
        entry = {"key": key, "stored_at": time.time(), "value": value}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, tmp_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
            )
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as tmp:
                    json.dump(entry, tmp, ensure_ascii=False)
                os.replace(tmp_name, path)
            finally:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
        except OSError as exc:
            LOGGER.debug("Could not write cache entry: %s", exc)
