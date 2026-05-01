# nvd-mirror

<table>
	<thead>
		<tr>
			<th style="text-align:center"><a href="README.md">English</a></th>
			<th style="text-align:center">日本語</th>
		</tr>
	</thead>
</table>

`nvd-mirror` は、NVD CVE API 2.0 から CVE レコードを取得し、ローカルに JSON ファイルとして保存するための小さな Python CLI です。

長時間実行されるローカルミラーを想定しており、中断された処理を checkpoint から再開できます。

## 機能

- `pubStartDate` / `pubEndDate` を使った初期化
- `lastModStartDate` / `lastModEndDate` を使った差分同期
- init / sync の中断再開に対応した checkpoint
- `cves/<CVE-IDの年>/` 配下へ 1 CVE 1 JSON ファイルで保存
- TOML 設定ファイル
- 一時的な HTTP / 通信エラーに対する retry
- request parameter、response summary、保存件数、保存ファイル一覧を表示する verbose mode

## 要件

- Python 3.10 以上
- `requests`
- Python 3.11 未満では `tomli`

依存関係のインストール:

```bash
python3 -m pip install -r requirements.txt
```

開発とテスト用:

```bash
python3 -m pip install -r requirements-dev.txt
```

## クイックスタート

設定ファイルを作成します。

```bash
cp nvd-mirror.example.toml nvd-mirror.toml
```

`nvd-mirror.toml` を編集します。

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

ミラーを初期化します。

```bash
python3 nvd_mirror.py --init --path ./mirror
```

差分同期を実行します。

```bash
python3 nvd_mirror.py --sync --path ./mirror
```

現在の checkpoint 状態を表示します。

```bash
python3 nvd_mirror.py --status --path ./mirror
```

中断された処理を明示的に再開します。

```bash
python3 nvd_mirror.py --resume --path ./mirror
```

## Verbose Mode

`--verbose` を付けると、request と保存処理の詳細を表示します。

```bash
python3 nvd_mirror.py --sync --verbose --path ./mirror
```

出力例:

```text
verbose: request {"lastModEndDate": "...", "lastModStartDate": "...", "resultsPerPage": 500, "startIndex": 0}
verbose: attempt 1/4
verbose: response totalResults=127 vulnerabilities=127
verbose: saved 127 CVEs
verbose: saved file cves/2025/CVE-2025-0001.json
```

## データレイアウト

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

`checkpoint.json` は中断再開に使われます。正常終了後は削除されます。

## ソースレイアウト

```text
nvd_mirror.py          # CLI wrapper
nvd_mirror/
  api.py               # NVD API client and API errors
  cli.py               # Argument parser and main()
  config.py            # TOML configuration loading and validation
  mirror.py            # Init, sync, resume, and status runner
  storage.py           # State, checkpoint, working files, and CVE writes
```

## テスト

設定読み込み、init resume、sync state、verbose logging、retry、CVE ファイル出力に対する pytest テストを含んでいます。

```bash
python3 -m pytest tests/test_nvd_mirror.py
```

## 注意点

- init は内部的に NVD の `published` date window を固定初期範囲から順に処理し、現在の window を `checkpoint.json` に保存して安定して再開できるようにします。
- `CVE-2010-...` のような古い ID の CVE でも、初期化対象の published-date range に含まれる NVD レコードであれば保存されることがあります。
- `cves/` 配下のディレクトリは、CVE ID に含まれる年を使います。
- `results_per_page=500` は安定性重視の保守的な既定値です。NVD は最大 2000 件まで許容しますが、大きな response は遅くなったり中断されたりしやすくなります。
- API key は rate limit の改善に役立ちますが、個々の request が必ず速くなるとは限りません。

## ライセンス

このリポジトリで公開するライセンスを追加してください。現在のリポジトリライセンスを使う場合は、対応する `LICENSE` ファイルを GitHub リポジトリに含めてください。
