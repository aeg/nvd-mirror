# GitHub repository information

## Suggested Repository Name

`nvd-mirror`

## Short Description

Checkpoint-based local mirror client for the NVD CVE API 2.0.

## Website / Homepage

Leave empty unless a documentation page is published.

## Topics

- `nvd`
- `cve`
- `vulnerability`
- `security`
- `mirror`
- `nvd-api`
- `python`
- `cli`

## About Text

`nvd-mirror` is a Python CLI for building and maintaining a local mirror of CVE records from the NVD CVE API 2.0. It supports full initialization, incremental sync, checkpoint-based resume, retries, and verbose operational logging.

## Suggested Initial Repository Files

- `nvd_mirror.py`
- `README.md`
- `requirements.txt`
- `requirements-dev.txt`
- `nvd-mirror.example.toml`
- `tests/test_nvd_mirror.py`
- `.gitignore`
- `LICENSE`

## Suggested README Highlights

- Explain that init uses `pubStartDate` / `pubEndDate`
- Explain that sync uses `lastModStartDate` / `lastModEndDate`
- Explain checkpoint resume behavior
- Explain that CVE ID year and NVD published date are different concepts
- Recommend `results_per_page=500` for stable operation

## Caveats To Mention

- NVD API responses can be slow or unstable for large result pages.
- A lower `results_per_page` can improve reliability at the cost of more API calls.
- CVE ID year and NVD published date are different concepts, so old CVE IDs can appear in later published-date windows.
- API key usage helps rate limits but does not guarantee lower response latency.

## Example GitHub Release Title

`Initial nvd-mirror CLI release`

## Example GitHub Release Notes

Initial release of `nvd-mirror`, a Python CLI for maintaining a local CVE mirror from the NVD CVE API 2.0.

Included:

- Full initialization by NVD published date
- Incremental sync by NVD last modified date
- Checkpoint-based resume for interrupted runs
- TOML configuration
- Retry handling for transient request failures
- Verbose operational logging
- Pytest-based unit tests
