#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import requests

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 2000
MAX_WINDOW_DAYS = 120
INITIAL_PUBLISH_START = datetime(1999, 1, 1, tzinfo=timezone.utc)
ERROR_BODY_LIMIT = 1000
DEFAULT_HTTP_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 5.0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def format_seconds(seconds: float) -> str:
    total_seconds = max(0, int(round(seconds)))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


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


class NvdApiClient:
    def __init__(self, config: AppConfig):
        self.config = config

    def fetch_cves(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Accept-Language": "en-US",
            "User-Agent": self.config.user_agent,
        }
        if self.config.api_key:
            headers["apiKey"] = self.config.api_key

        response = requests.get(
            API_URL,
            params=params,
            headers=headers,
            timeout=self.config.http_timeout,
        )
        if response.status_code >= 400:
            body = response.text[:ERROR_BODY_LIMIT]
            raise NvdApiError(
                "NVD API request failed: "
                f"status={response.status_code} url={response.url} body={body!r}",
                status_code=response.status_code,
            )
        payload = response.json()
        time.sleep(self.config.sleep_seconds())
        return payload


class NvdApiError(RuntimeError):
    def __init__(self, message: str, *, status_code: int):
        super().__init__(message)
        self.status_code = status_code


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


class MirrorRunner:
    def __init__(
        self,
        config: AppConfig,
        api_client: NvdApiClient,
        now_fn: Callable[[], datetime] = utc_now,
        output: Callable[[str], None] = print,
        verbose: bool = False,
    ):
        self.config = config
        self.api_client = api_client
        self.now_fn = now_fn
        self.output = output
        self.verbose = verbose
        ensure_directories(config)

    def verbose_output(self, message: str) -> None:
        if self.verbose:
            self.output(f"verbose: {message}")

    def record_response(self, payload: dict[str, Any]) -> None:
        self.verbose_output(
            "response "
            f"totalResults={payload.get('totalResults')} "
            f"vulnerabilities={len(payload.get('vulnerabilities', []))}"
        )

    def save_payload(self, payload: dict[str, Any]) -> int:
        saved_paths = save_cves(self.config, payload)
        self.verbose_output(f"saved {len(saved_paths)} CVEs")
        for saved_path in saved_paths:
            relative_path = saved_path.relative_to(self.config.mirror_path).as_posix()
            self.verbose_output(f"saved file {relative_path}")
        return len(saved_paths)

    def fetch_cves(self, params: dict[str, Any]) -> dict[str, Any]:
        max_attempts = self.config.http_retries + 1
        for attempt in range(1, max_attempts + 1):
            try:
                self.verbose_output(f"attempt {attempt}/{max_attempts}")
                return self.api_client.fetch_cves(params)
            except Exception as exc:
                if not self.is_retryable_error(exc) or attempt >= max_attempts:
                    raise
                self.verbose_output(
                    f"retryable error {type(exc).__name__}: {exc}"
                )
                delay = self.config.retry_backoff * attempt
                self.verbose_output(f"sleeping {delay:.1f}s before retry")
                time.sleep(delay)
        raise RuntimeError("unreachable retry state")

    @staticmethod
    def is_retryable_error(exc: Exception) -> bool:
        if isinstance(exc, requests.exceptions.RequestException):
            return True
        if isinstance(exc, NvdApiError):
            return (
                exc.status_code == 429
                or 500 <= exc.status_code <= 599
            )
        return False

    def run_init(self, run_end: Optional[datetime] = None) -> int:
        checkpoint = maybe_load_checkpoint(self.config)
        if checkpoint and checkpoint.get("mode") == "init":
            return self.resume_init(checkpoint)

        started_at = self.now_fn()
        end_at = run_end or started_at
        init_start = INITIAL_PUBLISH_START

        if init_start >= end_at:
            raise ValueError("no initialization windows were generated")

        checkpoint = {
            "mode": "init",
            "run_id": started_at.strftime("%Y%m%dT%H%M%S"),
            "started_at": isoformat_z(started_at),
            "run_end": isoformat_z(end_at),
            "next_pub_start": isoformat_z(init_start),
            "current_pub_end": isoformat_z(
                min(init_start + timedelta(days=MAX_WINDOW_DAYS), end_at)
            ),
            "start_index": 0,
            "results_per_page": self.config.results_per_page,
            "total_results": None,
            "saved_total": 0,
            "window_saved_total": 0,
            "avg_page_seconds": 0.0,
        }
        update_state(
            self.config,
            init_completed=False,
            init_progress=None,
        )
        prepare_working_dir(self.config, checkpoint)
        save_checkpoint(self.config, checkpoint)
        self._continue_init(checkpoint)

        update_state(
            self.config,
            init_completed=True,
            init_progress=None,
            next_sync_from=isoformat_z(started_at),
        )
        clear_checkpoint(self.config)
        clear_working_dir(self.config)
        return 0

    def resume_init(self, checkpoint: dict[str, Any]) -> int:
        prepare_working_dir(self.config, checkpoint)
        checkpoint.setdefault("window_saved_total", checkpoint.get("start_index", 0))
        self._continue_init(checkpoint)
        update_state(
            self.config,
            init_completed=True,
            init_progress=None,
            next_sync_from=checkpoint["started_at"],
        )
        clear_checkpoint(self.config)
        clear_working_dir(self.config)
        return 0

    def _continue_init(self, checkpoint: dict[str, Any]) -> None:
        run_end = parse_datetime(checkpoint["run_end"])
        while parse_datetime(checkpoint["next_pub_start"]) < run_end:
            window_start = parse_datetime(checkpoint["next_pub_start"])
            window_end = parse_datetime(checkpoint["current_pub_end"])
            checkpoint.setdefault("start_index", 0)
            checkpoint.setdefault("saved_total", 0)
            checkpoint.setdefault("window_saved_total", checkpoint["start_index"])
            save_checkpoint(self.config, checkpoint)

            while True:
                params = {
                    "pubStartDate": isoformat_z(window_start),
                    "pubEndDate": isoformat_z(window_end),
                    "resultsPerPage": self.config.results_per_page,
                    "startIndex": checkpoint["start_index"],
                }
                self.verbose_output(
                    f"request {json.dumps(params, sort_keys=True)}"
                )
                page_started = time.monotonic()
                payload = self.fetch_cves(params)
                self.record_response(payload)
                save_working_page(
                    self.config,
                    checkpoint["start_index"] // self.config.results_per_page,
                    payload,
                )
                saved_count = self.save_payload(payload)
                elapsed = time.monotonic() - page_started
                checkpoint["total_results"] = payload["totalResults"]
                checkpoint["start_index"] += saved_count
                checkpoint["saved_total"] += saved_count
                checkpoint["window_saved_total"] += saved_count
                checkpoint["avg_page_seconds"] = self._update_avg(
                    checkpoint.get("avg_page_seconds", 0.0), elapsed
                )
                save_checkpoint(self.config, checkpoint)
                self.output(render_status_line(checkpoint))

                if checkpoint["start_index"] >= payload["totalResults"]:
                    next_pub_start = window_end
                    checkpoint["next_pub_start"] = isoformat_z(next_pub_start)
                    checkpoint["current_pub_end"] = isoformat_z(
                        min(next_pub_start + timedelta(days=MAX_WINDOW_DAYS), run_end)
                    )
                    checkpoint["start_index"] = 0
                    checkpoint["window_saved_total"] = 0
                    checkpoint["total_results"] = None
                    save_checkpoint(self.config, checkpoint)
                    break

    def run_sync(self, run_end: Optional[datetime] = None) -> int:
        checkpoint = maybe_load_checkpoint(self.config)
        if checkpoint:
            if checkpoint.get("mode") == "sync":
                return self.resume_sync(checkpoint)
            if checkpoint.get("mode") == "init":
                raise ValueError(
                    "initialization is not complete; run --init to resume initialization before sync"
                )

        state = load_state(self.config)
        if not state.get("init_completed"):
            raise ValueError(
                "initialization is not complete; run --init before sync"
            )
        if "next_sync_from" not in state:
            raise ValueError("state file is required before sync")

        range_start = parse_datetime(state["next_sync_from"])
        range_end = run_end or self.now_fn()
        checkpoint = {
            "mode": "sync",
            "run_id": range_end.strftime("%Y%m%dT%H%M%S"),
            "started_at": isoformat_z(self.now_fn()),
            "range_start": isoformat_z(range_start),
            "range_end": isoformat_z(range_end),
            "start_index": 0,
            "results_per_page": self.config.results_per_page,
            "total_results": None,
            "saved_total": 0,
            "avg_page_seconds": 0.0,
        }
        prepare_working_dir(self.config, checkpoint)
        save_checkpoint(self.config, checkpoint)
        self._continue_sync(checkpoint)
        state["next_sync_from"] = isoformat_z(range_end)
        save_state(self.config, state)
        clear_checkpoint(self.config)
        clear_working_dir(self.config)
        return 0

    def resume_sync(self, checkpoint: dict[str, Any]) -> int:
        prepare_working_dir(self.config, checkpoint)
        self._continue_sync(checkpoint)
        state = load_state(self.config)
        state["next_sync_from"] = checkpoint["range_end"]
        save_state(self.config, state)
        clear_checkpoint(self.config)
        clear_working_dir(self.config)
        return 0

    def _continue_sync(self, checkpoint: dict[str, Any]) -> None:
        while True:
            params = {
                "lastModStartDate": checkpoint["range_start"],
                "lastModEndDate": checkpoint["range_end"],
                "resultsPerPage": self.config.results_per_page,
                "startIndex": checkpoint["start_index"],
            }
            self.verbose_output(
                f"request {json.dumps(params, sort_keys=True)}"
            )
            page_started = time.monotonic()
            payload = self.fetch_cves(params)
            self.record_response(payload)
            save_working_page(
                self.config,
                checkpoint["start_index"] // self.config.results_per_page,
                payload,
            )
            saved_count = self.save_payload(payload)
            elapsed = time.monotonic() - page_started
            checkpoint["total_results"] = payload["totalResults"]
            checkpoint["start_index"] += saved_count
            checkpoint["saved_total"] += saved_count
            checkpoint["avg_page_seconds"] = self._update_avg(
                checkpoint.get("avg_page_seconds", 0.0), elapsed
            )
            save_checkpoint(self.config, checkpoint)
            self.output(render_status_line(checkpoint))

            if checkpoint["start_index"] >= payload["totalResults"]:
                return

    def run_resume(self) -> int:
        checkpoint = load_checkpoint(self.config)
        if checkpoint["mode"] == "sync":
            return self.resume_sync(checkpoint)
        elif checkpoint["mode"] == "init":
            return self.resume_init(checkpoint)
        else:
            raise ValueError(f'unsupported checkpoint mode: {checkpoint["mode"]}')

    def run_status(self) -> int:
        checkpoint = load_checkpoint(self.config)
        self.output(render_status_line(checkpoint))
        return 0

    @staticmethod
    def _update_avg(previous: float, current: float) -> float:
        if previous <= 0:
            return current
        return round((previous + current) / 2, 3)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NVD mirror client")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--init", action="store_true", help="initialize mirror")
    modes.add_argument("--sync", action="store_true", help="sync changes")
    modes.add_argument("--resume", action="store_true", help="resume last run")
    modes.add_argument("--status", action="store_true", help="show progress")
    parser.add_argument("--path", type=Path, help="mirror path")
    parser.add_argument("--config", type=Path, help="path to TOML config file")
    parser.add_argument("--api-key", help="NVD API key")
    parser.add_argument("--sleep-with-api-key", type=float)
    parser.add_argument("--sleep-without-api-key", type=float)
    parser.add_argument("--results-per-page", type=int)
    parser.add_argument("--http-timeout", type=float)
    parser.add_argument("--http-retries", type=int)
    parser.add_argument("--retry-backoff", type=float)
    parser.add_argument("--user-agent")
    parser.add_argument("--run-end", help="fixed run end datetime for testing or batch control")
    parser.add_argument("--verbose", action="store_true", help="show verbose progress details")
    return parser


def main(
    argv: Optional[list[str]] = None,
    *,
    api_client_factory: Optional[Callable[[AppConfig], NvdApiClient]] = None,
    now_fn: Callable[[], datetime] = utc_now,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = resolve_config(args)
        api_client_factory = api_client_factory or NvdApiClient
        runner = MirrorRunner(
            config,
            api_client_factory(config),
            now_fn=now_fn,
            verbose=args.verbose,
        )

        run_end = parse_datetime(args.run_end) if args.run_end else None

        if args.init:
            return runner.run_init(run_end=run_end)
        if args.sync:
            return runner.run_sync(run_end=run_end)
        if args.resume:
            return runner.run_resume()
        return runner.run_status()
    except Exception as exc:  # pragma: no cover - CLI guard
        print(str(exc), file=sys.stderr)
        if getattr(args, "verbose", False):
            print("verbose: exception details:", file=sys.stderr)
            traceback.print_exception(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
