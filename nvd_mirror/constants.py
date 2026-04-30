from __future__ import annotations

from datetime import datetime, timezone


API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 2000
MAX_WINDOW_DAYS = 120
INITIAL_PUBLISH_START = datetime(1999, 1, 1, tzinfo=timezone.utc)
ERROR_BODY_LIMIT = 1000
DEFAULT_HTTP_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 5.0
