from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import requests

from .api import NvdApiError
from .constants import INITIAL_PUBLISH_START, MAX_WINDOW_DAYS
from .manifest import write_manifest
from .storage import (
    clear_checkpoint,
    clear_working_dir,
    ensure_directories,
    load_checkpoint,
    load_state,
    maybe_load_checkpoint,
    prepare_working_dir,
    render_status_line,
    save_checkpoint,
    save_cves,
    save_state,
    save_working_page,
    update_state,
)
from .time_utils import isoformat_z, parse_datetime, utc_now

if TYPE_CHECKING:
    from collections.abc import Callable

    from .api import NvdApiClient
    from .config import AppConfig

HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVER_ERROR_MIN = 500
HTTP_SERVER_ERROR_MAX = 599


class MirrorRunner:
    def __init__(
        self,
        config: AppConfig,
        api_client: NvdApiClient,
        *,
        now_fn: Callable[[], datetime] = utc_now,
        output: Callable[[str], None] = print,
        verbose: bool = False,
    ) -> None:
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
            f"vulnerabilities={len(payload.get('vulnerabilities', []))}",
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
                    f"retryable error {type(exc).__name__}: {exc}",
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
                exc.status_code == HTTP_TOO_MANY_REQUESTS
                or HTTP_SERVER_ERROR_MIN <= exc.status_code <= HTTP_SERVER_ERROR_MAX
            )
        return False

    def run_init(self, run_end: datetime | None = None) -> int:
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
                min(init_start + timedelta(days=MAX_WINDOW_DAYS), end_at),
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
                    f"request {json.dumps(params, sort_keys=True)}",
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
                    checkpoint.get("avg_page_seconds", 0.0),
                    elapsed,
                )
                save_checkpoint(self.config, checkpoint)
                self.output(render_status_line(checkpoint))

                if checkpoint["start_index"] >= payload["totalResults"]:
                    next_pub_start = window_end
                    checkpoint["next_pub_start"] = isoformat_z(next_pub_start)
                    checkpoint["current_pub_end"] = isoformat_z(
                        min(next_pub_start + timedelta(days=MAX_WINDOW_DAYS), run_end),
                    )
                    checkpoint["start_index"] = 0
                    checkpoint["window_saved_total"] = 0
                    checkpoint["total_results"] = None
                    save_checkpoint(self.config, checkpoint)
                    break

    def run_sync(self, run_end: datetime | None = None) -> int:
        checkpoint = maybe_load_checkpoint(self.config)
        if checkpoint:
            if checkpoint.get("mode") == "sync":
                return self.resume_sync(checkpoint)
            if checkpoint.get("mode") == "init":
                message = (
                    "initialization is not complete; "
                    "run --init to resume initialization before sync"
                )
                raise ValueError(message)

        state = load_state(self.config)
        if not state.get("init_completed"):
            raise ValueError(
                "initialization is not complete; run --init before sync",
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
                f"request {json.dumps(params, sort_keys=True)}",
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
                checkpoint.get("avg_page_seconds", 0.0),
                elapsed,
            )
            save_checkpoint(self.config, checkpoint)
            self.output(render_status_line(checkpoint))

            if checkpoint["start_index"] >= payload["totalResults"]:
                return

    def run_resume(self) -> int:
        checkpoint = load_checkpoint(self.config)
        if checkpoint["mode"] == "sync":
            return self.resume_sync(checkpoint)
        if checkpoint["mode"] == "init":
            return self.resume_init(checkpoint)
        raise ValueError(f"unsupported checkpoint mode: {checkpoint['mode']}")

    def run_status(self) -> int:
        checkpoint = load_checkpoint(self.config)
        self.output(render_status_line(checkpoint))
        return 0

    def run_manifest(self) -> int:
        path = write_manifest(self.config, self.now_fn())
        self.output(f"wrote manifest {path}")
        return 0

    @staticmethod
    def _update_avg(previous: float, current: float) -> float:
        if previous <= 0:
            return current
        return round((previous + current) / 2, 3)
