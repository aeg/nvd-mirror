# nvd-mirror

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
- `requests`
- `tomli` on Python versions earlier than 3.11

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

For development and tests:

```bash
python3 -m pip install -r requirements-dev.txt
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
python3 nvd_mirror.py --init --path ./mirror
```

Run an incremental sync:

```bash
python3 nvd_mirror.py --sync --path ./mirror
```

Show current checkpoint status:

```bash
python3 nvd_mirror.py --status --path ./mirror
```

Resume an interrupted job explicitly:

```bash
python3 nvd_mirror.py --resume --path ./mirror
```

## Verbose Mode

Use `--verbose` to print request and save details:

```bash
python3 nvd_mirror.py --sync --verbose --path ./mirror
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
  state/
    state.json
    checkpoint.json
  working/
    current-run/
      metadata.json
      page-000000.json
```

`checkpoint.json` is used for resuming interrupted runs. It is removed after successful completion.

## Tests

The repository includes pytest tests for configuration loading, init resume behavior, sync state handling, verbose logging, retry behavior, and CVE file output.

```bash
python3 -m pytest tests/test_nvd_mirror.py
```

## Notes

- Init internally scans NVD `published` date windows from the fixed initial range and stores the active window in `checkpoint.json` for stable resume.
- A CVE with an old ID, such as `CVE-2010-...`, may be saved whenever its NVD record appears in the initialized published-date range.
- The directory under `cves/` is based on the year embedded in the CVE ID.
- `results_per_page=500` is a conservative default for stability. NVD allows up to 2000, but large responses are more likely to be slow or interrupted.
- API keys improve rate limits, but do not necessarily make each individual request faster.

## License

Add the license you intend to publish with this repository. If this project keeps the current repository license, include the corresponding `LICENSE` file in the GitHub repository.
