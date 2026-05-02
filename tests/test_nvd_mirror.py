from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import nvd_mirror


@pytest.fixture(autouse=True)
def isolate_default_config(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        nvd_mirror.config,
        "default_config_path",
        lambda: tmp_path / "missing-nvd-mirror.toml",
    )


class FakeApiClient:
    def __init__(self, config, pages):
        self.config = config
        self.pages = pages
        self.calls = []

    def fetch_cves(self, params):
        key = tuple(sorted(params.items()))
        self.calls.append(dict(params))
        try:
            return self.pages[key]
        except KeyError as exc:
            raise AssertionError(f"unexpected params: {params}") from exc


class FailingApiClient:
    def __init__(self, config):
        self.config = config

    def fetch_cves(self, params):
        raise RuntimeError("boom from fake client")


class FlakyApiClient:
    def __init__(self, config, page):
        self.config = config
        self.page = page
        self.calls = 0

    def fetch_cves(self, params):
        self.calls += 1
        if self.calls == 1:
            raise nvd_mirror.requests.exceptions.ChunkedEncodingError(
                "Response ended prematurely",
            )
        return self.page


def build_page(total_results, vulnerabilities):
    return {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "totalResults": total_results,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-04-19T00:00:00.000",
        "vulnerabilities": [{"cve": item} for item in vulnerabilities],
    }


def iso(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def test_init_command_saves_cves_and_records_state(tmp_path: Path):
    started_at = datetime(1999, 1, 2, 0, 0, tzinfo=timezone.utc)
    params = {
        "pubStartDate": "1999-01-01T00:00:00.000Z",
        "pubEndDate": "1999-01-02T00:00:00.000Z",
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    pages = {
        tuple(sorted(params.items())): build_page(
            2,
            [
                {
                    "id": "CVE-2026-0001",
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                },
                {
                    "id": "CVE-2026-0002",
                    "published": "2026-01-02T00:00:00.000",
                    "lastModified": "2026-01-03T00:00:00.000",
                },
            ],
        ),
    }

    exit_code = nvd_mirror.main(
        [
            "--init",
            "--path",
            str(tmp_path),
            "--run-end",
            "1999-01-02T00:00:00Z",
        ],
        api_client_factory=lambda config: FakeApiClient(config, pages),
        now_fn=lambda: started_at,
    )

    assert exit_code == 0
    assert (tmp_path / "cves" / "2026" / "CVE-2026-0001.json").is_file()
    assert not (tmp_path / "working" / "current-run").exists()

    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["init_completed"] is True
    assert state["next_sync_from"] == iso(started_at)


def test_verbose_mode_reports_request_and_saved_count(tmp_path: Path, capsys):
    started_at = datetime(1999, 1, 2, 0, 0, tzinfo=timezone.utc)
    params = {
        "pubStartDate": "1999-01-01T00:00:00.000Z",
        "pubEndDate": "1999-01-02T00:00:00.000Z",
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    pages = {
        tuple(sorted(params.items())): build_page(
            1,
            [
                {
                    "id": "CVE-2026-0201",
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                },
            ],
        ),
    }

    exit_code = nvd_mirror.main(
        [
            "--init",
            "--verbose",
            "--path",
            str(tmp_path),
            "--run-end",
            "1999-01-02T00:00:00Z",
        ],
        api_client_factory=lambda config: FakeApiClient(config, pages),
        now_fn=lambda: started_at,
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "verbose: request" in captured.out
    assert '"pubStartDate": "1999-01-01T00:00:00.000Z"' in captured.out
    assert '"resultsPerPage": 2000' in captured.out
    assert "verbose: response totalResults=1 vulnerabilities=1" in captured.out
    assert "verbose: saved 1 CVEs" in captured.out
    assert "verbose: saved file" in captured.out
    assert "cves/2026/CVE-2026-0201.json" in captured.out


def test_verbose_mode_reports_exception_details(tmp_path: Path, capsys):
    exit_code = nvd_mirror.main(
        [
            "--init",
            "--verbose",
            "--path",
            str(tmp_path),
            "--run-end",
            "1999-01-02T00:00:00Z",
        ],
        api_client_factory=FailingApiClient,
        now_fn=lambda: datetime(1999, 1, 2, 0, 0, tzinfo=timezone.utc),
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "boom from fake client" in captured.err
    assert "verbose: exception details:" in captured.err
    assert "Traceback (most recent call last):" in captured.err


def test_verbose_mode_retries_transient_chunked_response_error(
    tmp_path: Path,
    capsys,
):
    page = build_page(
        1,
        [
            {
                "id": "CVE-2026-0301",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
            },
        ],
    )
    flaky_client = FlakyApiClient(None, page)

    exit_code = nvd_mirror.main(
        [
            "--init",
            "--verbose",
            "--path",
            str(tmp_path),
            "--run-end",
            "1999-01-02T00:00:00Z",
            "--retry-backoff",
            "0",
            "--sleep-without-api-key",
            "0",
        ],
        api_client_factory=lambda config: flaky_client,
        now_fn=lambda: datetime(1999, 1, 2, 0, 0, tzinfo=timezone.utc),
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert flaky_client.calls == 2
    assert "verbose: attempt 1/4" in captured.out
    assert "verbose: retryable error ChunkedEncodingError" in captured.out
    assert "verbose: attempt 2/4" in captured.out
    assert (tmp_path / "cves" / "2026" / "CVE-2026-0301.json").is_file()


def test_sync_command_uses_saved_sync_point(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text(
        json.dumps(
            {
                "init_completed": True,
                "next_sync_from": "2026-04-19T00:00:00.000Z",
            },
        ),
    )

    params = {
        "lastModStartDate": "2026-04-19T00:00:00.000Z",
        "lastModEndDate": "2026-04-19T02:00:00.000Z",
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    pages = {
        tuple(sorted(params.items())): build_page(
            1,
            [
                {
                    "id": "CVE-2026-9999",
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-04-19T01:00:00.000",
                },
            ],
        ),
    }

    exit_code = nvd_mirror.main(
        [
            "--sync",
            "--path",
            str(tmp_path),
            "--run-end",
            "2026-04-19T02:00:00Z",
        ],
        api_client_factory=lambda config: FakeApiClient(config, pages),
        now_fn=lambda: datetime(2026, 4, 19, 2, 0, tzinfo=timezone.utc),
    )

    assert exit_code == 0
    state = json.loads((state_dir / "state.json").read_text())
    assert state["next_sync_from"] == "2026-04-19T02:00:00.000Z"
    assert (tmp_path / "cves" / "2026" / "CVE-2026-9999.json").is_file()


def test_manifest_command_writes_completed_mirror_metadata(tmp_path: Path, capsys):
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    state = {
        "init_completed": True,
        "next_sync_from": "2026-04-19T02:00:00.000Z",
    }
    (state_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")

    cve_dir = tmp_path / "cves" / "2026"
    cve_dir.mkdir(parents=True)
    (cve_dir / "CVE-2026-0001.json").write_text(
        json.dumps({"id": "CVE-2026-0001"}, sort_keys=True),
        encoding="utf-8",
    )
    (cve_dir / "CVE-2026-0002.json").write_text(
        json.dumps({"id": "CVE-2026-0002"}, sort_keys=True),
        encoding="utf-8",
    )

    exit_code = nvd_mirror.main(
        ["--manifest", "--path", str(tmp_path)],
        now_fn=lambda: datetime(2026, 5, 2, 12, 0, tzinfo=timezone.utc),
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "wrote manifest" in captured.out

    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["schema_version"] == 1
    assert manifest["generated_at"] == "2026-05-02T12:00:00.000Z"
    assert manifest["state"] == state
    assert manifest["files"]["cve_count"] == 2
    assert manifest["files"]["years"] == {"2026": 2}
    assert len(manifest["files"]["cves_sha256"]) == 64
    assert len(manifest["files"]["state_sha256"]) == 64
    assert "not endorsed or certified by the NVD" in manifest["source"]["notice"]


def test_manifest_command_requires_completed_init(tmp_path: Path, capsys):
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text(
        json.dumps({"init_completed": False}),
        encoding="utf-8",
    )

    exit_code = nvd_mirror.main(["--manifest", "--path", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "init must complete" in captured.err


def test_init_command_resumes_saved_init_checkpoint(tmp_path: Path):
    checkpoint_dir = tmp_path / "state"
    checkpoint_dir.mkdir(parents=True)
    checkpoint = {
        "mode": "init",
        "started_at": "2026-04-19T00:00:00.000Z",
        "run_end": "2026-04-19T00:00:00.000Z",
        "next_pub_start": "2026-01-01T00:00:00.000Z",
        "current_pub_end": "2026-04-19T00:00:00.000Z",
        "start_index": 2000,
        "results_per_page": 2000,
        "total_results": 2001,
        "saved_total": 2000,
        "window_saved_total": 2000,
        "avg_page_seconds": 1.0,
    }
    (checkpoint_dir / "checkpoint.json").write_text(json.dumps(checkpoint))

    params = {
        "pubStartDate": "2026-01-01T00:00:00.000Z",
        "pubEndDate": "2026-04-19T00:00:00.000Z",
        "resultsPerPage": 2000,
        "startIndex": 2000,
    }
    pages = {
        tuple(sorted(params.items())): build_page(
            2001,
            [
                {
                    "id": "CVE-2026-2001",
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-04-19T01:59:59.000",
                },
            ],
        ),
    }

    exit_code = nvd_mirror.main(
        [
            "--init",
            "--path",
            str(tmp_path),
            "--run-end",
            "2026-04-19T00:00:00Z",
        ],
        api_client_factory=lambda config: FakeApiClient(config, pages),
        now_fn=lambda: datetime(2026, 4, 19, 0, 1, tzinfo=timezone.utc),
    )

    assert exit_code == 0
    assert not (checkpoint_dir / "checkpoint.json").exists()
    assert (tmp_path / "cves" / "2026" / "CVE-2026-2001.json").is_file()
    state = json.loads((checkpoint_dir / "state.json").read_text())
    assert state["init_completed"] is True


def test_init_resume_uses_checkpoint_start_index(tmp_path: Path):
    checkpoint_dir = tmp_path / "state"
    checkpoint_dir.mkdir(parents=True)
    (checkpoint_dir / "checkpoint.json").write_text(
        json.dumps(
            {
                "mode": "init",
                "started_at": "2026-04-19T00:00:00.000Z",
                "run_end": "2026-04-19T00:00:00.000Z",
                "next_pub_start": "2026-01-01T00:00:00.000Z",
                "current_pub_end": "2026-04-19T00:00:00.000Z",
                "start_index": 2000,
                "results_per_page": 2000,
                "total_results": 2001,
                "saved_total": 2000,
                "window_saved_total": 2000,
                "avg_page_seconds": 1.0,
            },
        ),
    )

    params = {
        "pubStartDate": "2026-01-01T00:00:00.000Z",
        "pubEndDate": "2026-04-19T00:00:00.000Z",
        "resultsPerPage": 2000,
        "startIndex": 2000,
    }
    pages = {
        tuple(sorted(params.items())): build_page(
            2001,
            [
                {
                    "id": "CVE-2026-2002",
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-04-19T01:59:59.000",
                },
            ],
        ),
    }

    exit_code = nvd_mirror.main(
        [
            "--init",
            "--path",
            str(tmp_path),
            "--run-end",
            "2026-04-19T00:00:00Z",
        ],
        api_client_factory=lambda config: FakeApiClient(config, pages),
        now_fn=lambda: datetime(2026, 4, 19, 0, 1, tzinfo=timezone.utc),
    )

    assert exit_code == 0
    assert (tmp_path / "cves" / "2026" / "CVE-2026-2002.json").is_file()


def test_init_pages_until_all_results_are_saved(tmp_path: Path):
    first_params = {
        "pubStartDate": "1999-01-01T00:00:00.000Z",
        "pubEndDate": "1999-01-02T00:00:00.000Z",
        "resultsPerPage": 2,
        "startIndex": 0,
    }
    second_params = {
        "pubStartDate": "1999-01-01T00:00:00.000Z",
        "pubEndDate": "1999-01-02T00:00:00.000Z",
        "resultsPerPage": 2,
        "startIndex": 2,
    }
    pages = {
        tuple(sorted(first_params.items())): build_page(
            3,
            [
                {
                    "id": "CVE-2026-3331",
                    "published": "2026-05-01T00:00:00.000",
                    "lastModified": "2026-05-02T00:00:00.000",
                },
                {
                    "id": "CVE-2026-3332",
                    "published": "2026-05-01T00:00:00.000",
                    "lastModified": "2026-05-02T00:00:00.000",
                },
            ],
        ),
        tuple(sorted(second_params.items())): build_page(
            3,
            [
                {
                    "id": "CVE-2026-3333",
                    "published": "2026-05-02T00:00:00.000",
                    "lastModified": "2026-05-03T00:00:00.000",
                },
            ],
        ),
    }
    fake_client = FakeApiClient(None, pages)

    exit_code = nvd_mirror.main(
        [
            "--init",
            "--path",
            str(tmp_path),
            "--results-per-page",
            "2",
            "--run-end",
            "1999-01-02T00:00:00Z",
        ],
        api_client_factory=lambda config: fake_client,
        now_fn=lambda: datetime(1999, 1, 2, 0, 0, tzinfo=timezone.utc),
    )

    assert exit_code == 0
    assert fake_client.calls == [first_params, second_params]
    assert (tmp_path / "cves" / "2026" / "CVE-2026-3333.json").is_file()


def test_sync_command_fails_when_init_is_incomplete(tmp_path: Path, capsys):
    checkpoint_dir = tmp_path / "state"
    checkpoint_dir.mkdir(parents=True)
    (checkpoint_dir / "checkpoint.json").write_text(
        json.dumps(
            {
                "mode": "init",
                "run_end": "2026-04-19T00:00:00.000Z",
                "current_window_index": 0,
                "total_windows": 1,
                "window_start": "2026-01-01T00:00:00.000Z",
                "window_end": "2026-04-19T00:00:00.000Z",
                "start_index": 0,
                "results_per_page": 2000,
                "saved_total": 0,
            },
        ),
    )

    exit_code = nvd_mirror.main(["--sync", "--path", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--init" in captured.err
    assert "initialization" in captured.err


def test_status_command_shows_progress_and_eta(tmp_path: Path, capsys):
    checkpoint_dir = tmp_path / "state"
    checkpoint_dir.mkdir(parents=True)
    (checkpoint_dir / "checkpoint.json").write_text(
        json.dumps(
            {
                "mode": "sync",
                "range_start": "2026-04-19T00:00:00.000Z",
                "range_end": "2026-04-19T02:00:00.000Z",
                "start_index": 2000,
                "results_per_page": 2000,
                "total_results": 2450,
                "saved_total": 2000,
                "started_at": "2026-04-19T02:00:00.000Z",
                "avg_page_seconds": 18.0,
            },
        ),
    )

    exit_code = nvd_mirror.main(["--status", "--path", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "progress=81.6%" in captured.out
    assert "eta=00:00:18" in captured.out


def test_toml_config_is_saved_and_loaded(tmp_path: Path):
    config_path = tmp_path / "nvd-mirror.toml"
    mirror_path = tmp_path / "mirror-from-config"

    nvd_mirror.save_toml_config(
        config_path,
        {
            "mirror_path": str(mirror_path),
            "api_key": "secret",
            "sleep_with_api_key": 3.5,
            "sleep_without_api_key": 6.0,
            "results_per_page": 1000,
            "http_timeout": 45.0,
            "user_agent": "nvd-mirror-test",
        },
    )

    parser = nvd_mirror.build_parser()
    args = parser.parse_args(["--status", "--config", str(config_path)])
    config = nvd_mirror.resolve_config(args)

    assert config.mirror_path == mirror_path
    assert config.api_key == "secret"
    assert config.sleep_with_api_key == 3.5
    assert config.results_per_page == 1000
    assert config.user_agent == "nvd-mirror-test"


@pytest.mark.parametrize(
    "config_values",
    [
        {"mirror_path": "/tmp/mirror", "results_per_page": 2001},
        {"mirror_path": "/tmp/mirror", "results_per_page": 0},
        {"mirror_path": "/tmp/mirror", "sleep_with_api_key": -1},
        {"mirror_path": "/tmp/mirror", "sleep_without_api_key": -1},
        {"mirror_path": "/tmp/mirror", "http_timeout": 0},
    ],
)
def test_invalid_config_values_are_rejected(tmp_path: Path, config_values):
    config_path = tmp_path / "nvd-mirror.toml"
    nvd_mirror.save_toml_config(config_path, config_values)

    exit_code = nvd_mirror.main(["--status", "--config", str(config_path)])

    assert exit_code == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["--sync"],
        ["--resume"],
    ],
)
def test_commands_fail_without_required_state(tmp_path: Path, argv):
    exit_code = nvd_mirror.main([*argv, "--path", str(tmp_path)])

    assert exit_code == 1
