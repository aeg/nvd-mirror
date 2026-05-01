# Release checklist

Use this checklist before publishing `nvd-mirror.py` as a GitHub repository.

## Files

- [ ] Copy `nvd-mirror.py` into the repository root.
- [ ] Copy `requirements.txt`.
- [ ] Copy `requirements-dev.txt`.
- [ ] Copy `nvd-mirror.example.toml`.
- [ ] Copy `tests/test_nvd_mirror.py`.
- [ ] Add or copy `LICENSE`.
- [ ] Add `README.md`.
- [ ] Add `.gitignore`.
- [ ] Do not include `nvd-mirror.toml` if it contains a real API key.
- [ ] Do not include local `mirror/`, `cves/`, `state/`, or `working/` data.

## Security

- [ ] Confirm no API key is committed.
- [ ] Confirm no local mirror data is committed.
- [ ] Confirm no local path from the development machine is committed.

## Verification

Run:

```bash
python3 -m py_compile nvd-mirror.py
python3 nvd-mirror.py --help
python3 -m pytest tests/test_nvd_mirror.py
```

Optional smoke tests:

```bash
python3 nvd-mirror.py --init --path /tmp/nvd-mirror-test --results-per-page 100 --verbose
python3 nvd-mirror.py --status --path /tmp/nvd-mirror-test
```

If the init completes:

```bash
python3 nvd-mirror.py --sync --path /tmp/nvd-mirror-test --results-per-page 100 --verbose
```

## Suggested Defaults

- `results_per_page = 500`
- `http_retries = 3`
- `retry_backoff = 5.0`
- `sleep_with_api_key = 6.0`
- `sleep_without_api_key = 6.0`

## GitHub Settings

- [ ] Repository description is set.
- [ ] Topics are set.
- [ ] Issues are enabled if external feedback is desired.
- [ ] Releases are enabled.
- [ ] Branch protection is configured if multiple contributors are expected.
