from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

from .constants import (
    DEFAULT_HTTP_RETRIES,
    DEFAULT_RESULTS_PER_PAGE,
    DEFAULT_RETRY_BACKOFF,
)


@dataclass
class AppConfig:
    mirror_path: Path
    api_key: Optional[str]
    sleep_with_api_key: float
    sleep_without_api_key: float
    results_per_page: int
    http_timeout: float
    http_retries: int
    retry_backoff: float
    user_agent: str

    def sleep_seconds(self) -> float:
        if self.api_key:
            return self.sleep_with_api_key
        return self.sleep_without_api_key


def default_config_path() -> Path:
    return Path.cwd() / "nvd-mirror.toml"


def load_toml_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return dict(data.get("default", data))


def save_toml_config(path: Path, config: dict[str, Any]) -> None:
    lines = ["[default]"]
    for key, value in config.items():
        if value is None:
            continue
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, (int, float)):
            rendered = str(value)
        else:
            rendered = json.dumps(str(value))
        lines.append(f"{key} = {rendered}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def config_value(
    args: argparse.Namespace,
    config_values: dict[str, Any],
    name: str,
    default: Any,
) -> Any:
    value = getattr(args, name)
    if value is not None:
        return value
    return config_values.get(name, default)


def resolve_config(args: argparse.Namespace) -> AppConfig:
    config_values = load_toml_config(args.config or default_config_path())
    mirror_path_raw = (
        args.path or config_values.get("mirror_path") or config_values.get("nvd_path")
    )
    if not mirror_path_raw:
        raise ValueError("mirror path is required; set --path or configure mirror_path")

    api_key = args.api_key
    if api_key is None:
        api_key = config_values.get("api_key") or None

    config = AppConfig(
        mirror_path=Path(mirror_path_raw),
        api_key=api_key,
        sleep_with_api_key=float(
            config_value(args, config_values, "sleep_with_api_key", "6.0")
        ),
        sleep_without_api_key=float(
            config_value(args, config_values, "sleep_without_api_key", "6.0")
        ),
        results_per_page=int(
            config_value(
                args,
                config_values,
                "results_per_page",
                str(DEFAULT_RESULTS_PER_PAGE),
            )
        ),
        http_timeout=float(config_value(args, config_values, "http_timeout", "30")),
        http_retries=int(
            config_value(
                args,
                config_values,
                "http_retries",
                str(DEFAULT_HTTP_RETRIES),
            )
        ),
        retry_backoff=float(
            config_value(
                args,
                config_values,
                "retry_backoff",
                str(DEFAULT_RETRY_BACKOFF),
            )
        ),
        user_agent=args.user_agent
        or config_values.get("user_agent", "nvd-api-client-v2"),
    )
    validate_config(config)
    return config


def validate_config(config: AppConfig) -> None:
    if not 1 <= config.results_per_page <= DEFAULT_RESULTS_PER_PAGE:
        raise ValueError("results_per_page must be between 1 and 2000")
    if config.sleep_with_api_key < 0:
        raise ValueError("sleep_with_api_key must be >= 0")
    if config.sleep_without_api_key < 0:
        raise ValueError("sleep_without_api_key must be >= 0")
    if config.http_timeout <= 0:
        raise ValueError("http_timeout must be > 0")
    if config.http_retries < 0:
        raise ValueError("http_retries must be >= 0")
    if config.retry_backoff < 0:
        raise ValueError("retry_backoff must be >= 0")
