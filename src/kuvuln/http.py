"""HTTP client with retries, rate-limit handling and offline support."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import __version__
from .utils import wait_backoff

LOGGER = logging.getLogger("kuvuln.http")


class HttpError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, url: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.url = url


class OfflineError(HttpError):
    pass


class HttpClient:
    def __init__(
        self,
        timeout: float = 20.0,
        retries: int = 3,
        offline: bool = False,
        user_agent: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = max(0, retries)
        self.offline = offline
        self.user_agent = user_agent or f"KuVuln/{__version__} (security scanner)"

    def request(
        self,
        method: str,
        url: str,
        payload: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        accept: str = "application/json",
    ) -> bytes:
        if self.offline:
            raise OfflineError("Network access disabled by --offline", url=url)

        body: bytes | None = None
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": accept,
            **{k: v for k, v in (headers or {}).items() if v is not None},
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

        attempts = self.retries if retries is None else max(0, retries)
        last_error: Exception | None = None
        for attempt in range(attempts + 1):
            request = urllib.request.Request(
                url, data=body, headers=request_headers, method=method.upper()
            )
            try:
                with urllib.request.urlopen(
                    request, timeout=timeout or self.timeout
                ) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code in {429, 500, 502, 503, 504} and attempt < attempts:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    LOGGER.warning(
                        "HTTP %s from %s; retrying (%s/%s)",
                        exc.code,
                        _safe_url(url),
                        attempt + 1,
                        attempts,
                    )
                    wait_backoff(attempt, retry_after)
                    continue
                detail = ""
                try:
                    detail = exc.read(300).decode("utf-8", "replace")
                except OSError:
                    pass
                raise HttpError(
                    f"HTTP {exc.code} from {_safe_url(url)} {detail}".strip(),
                    status=exc.code,
                    url=url,
                ) from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                if attempt < attempts:
                    LOGGER.warning(
                        "Network error from %s; retrying (%s/%s)",
                        _safe_url(url),
                        attempt + 1,
                        attempts,
                    )
                    wait_backoff(attempt)
                    continue
                raise HttpError(
                    f"Network error from {_safe_url(url)}: {exc}", url=url
                ) from exc

        raise HttpError(f"Request failed: {last_error}", url=url)

    def json(
        self,
        method: str,
        url: str,
        payload: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> Any:
        raw = self.request(
            method, url, payload=payload, headers=headers, timeout=timeout, retries=retries
        )
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HttpError(f"Invalid JSON from {_safe_url(url)}", url=url) from exc

    def text(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> str:
        raw = self.request(
            method,
            url,
            headers=headers,
            timeout=timeout,
            retries=retries,
            accept="text/plain, */*",
        )
        return raw.decode("utf-8", "replace")


def _safe_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"
