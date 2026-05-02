from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from .storage import atomic_write_json, load_state
from .time_utils import isoformat_z

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from .config import AppConfig


def manifest_file(config: AppConfig) -> Path:
    return config.mirror_path / "manifest.json"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _collect_cve_files(config: AppConfig) -> list[Path]:
    cves_dir = config.mirror_path / "cves"
    if not cves_dir.exists():
        return []
    return sorted(path for path in cves_dir.rglob("*.json") if path.is_file())


def _hash_cve_tree(config: AppConfig, cve_files: list[Path]) -> str:
    digest = hashlib.sha256()
    cves_dir = config.mirror_path / "cves"
    for path in cve_files:
        relative_path = path.relative_to(cves_dir).as_posix()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def build_manifest(config: AppConfig, generated_at: datetime) -> dict[str, Any]:
    state = load_state(config)
    if not state:
        raise ValueError("state file is required before writing a manifest")
    if not state.get("init_completed"):
        raise ValueError("init must complete before writing a manifest")

    cve_files = _collect_cve_files(config)
    years: dict[str, int] = {}
    total_size_bytes = 0
    for path in cve_files:
        year = path.parent.name
        years[year] = years.get(year, 0) + 1
        total_size_bytes += path.stat().st_size

    return {
        "schema_version": 1,
        "generated_at": isoformat_z(generated_at),
        "source": {
            "name": "NVD CVE API 2.0",
            "notice": (
                "This product uses the NVD API but is not endorsed or "
                "certified by the NVD."
            ),
        },
        "state": state,
        "files": {
            "cve_count": len(cve_files),
            "years": dict(sorted(years.items())),
            "total_size_bytes": total_size_bytes,
            "cves_sha256": _hash_cve_tree(config, cve_files),
            "state_sha256": _hash_file(config.mirror_path / "state" / "state.json"),
        },
    }


def write_manifest(config: AppConfig, generated_at: datetime) -> Path:
    path = manifest_file(config)
    atomic_write_json(path, build_manifest(config, generated_at))
    return path
