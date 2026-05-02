# nvd-mirror

<table>
	<thead>
		<tr>
			<th style="text-align:center">English</th>
			<th style="text-align:center"><a href="README_ja.md">日本語</a></th>
		</tr>
	</thead>
</table>

`nvd-mirror` is a small Python CLI for mirroring CVE records from the NVD CVE API 2.0 into local JSON files.

It is designed for long-running local mirrors where interrupted jobs must be resumable.

## Features

- Full initialization using `pubStartDate` / `pubEndDate`
- Incremental sync using `lastModStartDate` / `lastModEndDate`
- Checkpoint-based resume for interrupted init and sync runs
- One CVE per JSON file under `cves/<CVE-ID-year>/`
- TOML configuration
- Retry support for transient HTTP and connection errors
- Verbose mode for request parameters, response summaries, saved counts, and saved file paths

## Requirements

- Python 3.10 or later
- `uv`

Install `uv` if it is not already available:

```bash
python3 -m pip install uv
```

Project dependencies are defined in `pyproject.toml`. `uv run` creates or
updates the local environment automatically when you run a command.

For development tools and tests, use the `dev` dependency group:

```bash
uv sync --group dev
```

## Quick Start

Create a configuration file:

```bash
cp nvd-mirror.example.toml nvd-mirror.toml
```

Edit `nvd-mirror.toml`:

```toml
[default]
mirror_path = "./mirror"
api_key = ""
sleep_with_api_key = 6.0
sleep_without_api_key = 6.0
results_per_page = 500
http_timeout = 30
http_retries = 3
retry_backoff = 5.0
user_agent = "nvd-mirror"
```

Initialize a mirror:

```bash
uv run python nvd-mirror.py --init --path ./mirror
```

Run an incremental sync:

```bash
uv run python nvd-mirror.py --sync --path ./mirror
```

Write a manifest for a completed mirror:

```bash
uv run python nvd-mirror.py --manifest --path ./mirror
```

Verify a manually downloaded and extracted snapshot:

```bash
uv run python nvd-mirror.py --verify-manifest --path ./mirror
```

Show current checkpoint status:

```bash
uv run python nvd-mirror.py --status --path ./mirror
```

Resume an interrupted job explicitly:

```bash
uv run python nvd-mirror.py --resume --path ./mirror
```

## Verbose Mode

Use `--verbose` to print request and save details:

```bash
uv run python nvd-mirror.py --sync --verbose --path ./mirror
```

Example output:

```text
verbose: request {"lastModEndDate": "...", "lastModStartDate": "...", "resultsPerPage": 500, "startIndex": 0}
verbose: attempt 1/4
verbose: response totalResults=127 vulnerabilities=127
verbose: saved 127 CVEs
verbose: saved file cves/2025/CVE-2025-0001.json
```

## Data Layout

```text
<mirror_path>/
  cves/
    2025/
      CVE-2025-0001.json
  manifest.json
  state/
    state.json
    checkpoint.json
  working/
    current-run/
      metadata.json
      page-000000.json
```

`manifest.json` records snapshot metadata, CVE counts, and checksums for completed mirrors. Use `--verify-manifest` after manually downloading and extracting a snapshot to confirm that `cves/` and `state/state.json` still match the manifest. `checkpoint.json` is used for resuming interrupted runs. It is removed after successful completion.

## Source Layout

```text
nvd-mirror.py          # CLI wrapper
nvd_mirror/
  api.py               # NVD API client and API errors
  cli.py               # Argument parser and main()
  config.py            # TOML configuration loading and validation
  manifest.py          # Snapshot manifest generation
  mirror.py            # Init, sync, resume, and status runner
  storage.py           # State, checkpoint, working files, and CVE writes
```

## Tests

The repository includes pytest tests for configuration loading, init resume behavior, sync state handling, verbose logging, retry behavior, and CVE file output.

```bash
uv run --group dev pytest tests/test_nvd_mirror.py
```

Run Ruff checks:

```bash
uv run --group dev ruff check --config ruff.toml .
uv run --group dev ruff format --check --config ruff.toml .
```

## Notes

- Init internally scans NVD `published` date windows from the fixed initial range and stores the active window in `checkpoint.json` for stable resume.
- A CVE with an old ID, such as `CVE-2010-...`, may be saved whenever its NVD record appears in the initialized published-date range.
- The directory under `cves/` is based on the year embedded in the CVE ID.
- `results_per_page=500` is a conservative default for stability. NVD allows up to 2000, but large responses are more likely to be slow or interrupted.
- API keys improve rate limits, but do not necessarily make each individual request faster.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

Data retrieved from the NVD API is subject to the NVD/NIST terms of use and disclaimers. This project does not guarantee the accuracy, completeness, or timeliness of NVD API-derived data.
