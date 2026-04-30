from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Optional

from .config import AppConfig
from .constants import DEFAULT_RESULTS_PER_PAGE
from .time_utils import format_seconds


def ensure_directories(config: AppConfig) -> None:
    (config.mirror_path / "cves").mkdir(parents=True, exist_ok=True)
    (config.mirror_path / "state").mkdir(parents=True, exist_ok=True)
    (config.mirror_path / "working").mkdir(parents=True, exist_ok=True)


def state_file(config: AppConfig) -> Path:
    return config.mirror_path / "state" / "state.json"


def checkpoint_file(config: AppConfig) -> Path:
    return config.mirror_path / "state" / "checkpoint.json"


def working_dir(config: AppConfig) -> Path:
    return config.mirror_path / "working" / "current-run"


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    tmp_path.replace(path)


def load_state(config: AppConfig) -> dict[str, Any]:
    path = state_file(config)
    if not path.exists():
        return {}
    return load_json(path)


def save_state(config: AppConfig, state: dict[str, Any]) -> None:
    atomic_write_json(state_file(config), state)


def update_state(config: AppConfig, **updates: Any) -> dict[str, Any]:
    state = load_state(config)
    for key, value in updates.items():
        if value is None:
            state.pop(key, None)
        else:
            state[key] = value
    save_state(config, state)
    return state


def load_checkpoint(config: AppConfig) -> dict[str, Any]:
    path = checkpoint_file(config)
    if not path.exists():
        raise ValueError("checkpoint file does not exist")
    return load_json(path)


def maybe_load_checkpoint(config: AppConfig) -> Optional[dict[str, Any]]:
    path = checkpoint_file(config)
    if not path.exists():
        return None
    return load_json(path)


def save_checkpoint(config: AppConfig, checkpoint: dict[str, Any]) -> None:
    atomic_write_json(checkpoint_file(config), checkpoint)


def clear_checkpoint(config: AppConfig) -> None:
    path = checkpoint_file(config)
    if path.exists():
        path.unlink()


def clear_working_dir(config: AppConfig) -> None:
    path = working_dir(config)
    if path.exists():
        shutil.rmtree(path)


def prepare_working_dir(config: AppConfig, metadata: dict[str, Any]) -> None:
    clear_working_dir(config)
    path = working_dir(config)
    path.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path / "metadata.json", metadata)


def save_working_page(config: AppConfig, page_number: int, payload: dict[str, Any]) -> None:
    path = working_dir(config)
    path.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path / f"page-{page_number:06d}.json", payload)


def save_cves(config: AppConfig, payload: dict[str, Any]) -> list[Path]:
    saved_paths = []
    for item in payload.get("vulnerabilities", []):
        cve = item["cve"]
        year = cve["id"][4:8]
        target = config.mirror_path / "cves" / year / f'{cve["id"]}.json'
        atomic_write_json(target, cve)
        saved_paths.append(target)
    return saved_paths


def page_count(total_results: int, results_per_page: int) -> int:
    if total_results <= 0:
        return 0
    return ((total_results - 1) // results_per_page) + 1


def render_status_line(checkpoint: dict[str, Any]) -> str:
    if checkpoint["mode"] == "init":
        total = checkpoint.get("total_results") or 0
        saved = checkpoint.get("window_saved_total", 0)
    else:
        total = checkpoint.get("total_results") or 0
        saved = checkpoint.get("saved_total", 0)
    if total:
        progress = min(saved / total * 100.0, 100.0)
    else:
        progress = 0.0

    remaining = max(total - saved, 0)
    results_per_page = checkpoint.get("results_per_page", DEFAULT_RESULTS_PER_PAGE)
    remaining_pages = page_count(remaining, results_per_page)
    eta_seconds = checkpoint.get("avg_page_seconds", 0.0) * remaining_pages

    if checkpoint["mode"] == "init":
        scope = (
            f'window={checkpoint["next_pub_start"]}..{checkpoint["current_pub_end"]}'
        )
    else:
        scope = f'range={checkpoint["range_start"]}..{checkpoint["range_end"]}'

    return (
        f'mode={checkpoint["mode"]} {scope} '
        f'saved={saved}/{total} progress={progress:.1f}% eta={format_seconds(eta_seconds)}'
    )
