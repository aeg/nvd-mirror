from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import requests

from .constants import API_URL, ERROR_BODY_LIMIT

if TYPE_CHECKING:
    from .config import AppConfig

HTTP_BAD_REQUEST = 400


class NvdApiClient:
    def __init__(self, config: AppConfig) -> None:
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
        if response.status_code >= HTTP_BAD_REQUEST:
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
    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code
