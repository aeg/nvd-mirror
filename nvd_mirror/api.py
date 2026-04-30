from __future__ import annotations

import time
from typing import Any

import requests

from .config import AppConfig
from .constants import API_URL, ERROR_BODY_LIMIT


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
