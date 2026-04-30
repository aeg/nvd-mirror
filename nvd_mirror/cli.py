from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Callable, Optional

from .api import NvdApiClient
from .config import AppConfig, resolve_config
from .mirror import MirrorRunner
from .time_utils import parse_datetime, utc_now


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
    now_fn=utc_now,
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
