"""GitHub API helpers: sticky PR comments and job summaries."""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

from .http import HttpClient
from .reports import MARKER

LOGGER = logging.getLogger("kuvuln.github")


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(
        self,
        token: str | None = None,
        repository: str | None = None,
        api_url: str | None = None,
        offline: bool = False,
        timeout: float = 20,
    ) -> None:
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.repository = repository or os.getenv("GITHUB_REPOSITORY", "")
        self.api_url = (api_url or os.getenv("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
        self.offline = offline
        self.http = HttpClient(timeout=timeout, offline=offline, user_agent="KuVuln")

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, method: str, path: str, payload: Any = None) -> Any:
        if not self.token or not self.repository:
            raise GitHubError("GitHub token/repository not configured")
        url = f"{self.api_url}{path}"
        try:
            return self.http.json(
                method, url, payload=payload, headers=self._headers(), timeout=20, retries=2
            )
        except Exception as exc:
            raise GitHubError(str(exc)) from exc

    def upsert_pr_comment(self, pull_number: int, body: str) -> dict[str, Any]:
        if not body.startswith(MARKER):
            body = f"{MARKER}\n{body}"
        comments: list[dict[str, Any]] = []
        for page in range(1, 11):
            data = self._request(
                "GET",
                f"/repos/{quote(self.repository, safe='/')}/issues/{pull_number}"
                f"/comments?per_page=100&page={page}",
            )
            if not isinstance(data, list) or not data:
                break
            comments.extend(data)
        existing = None
        for comment in comments:
            if isinstance(comment, dict) and str(comment.get("body", "")).startswith(MARKER):
                existing = comment
                break
        if existing is not None:
            comment_id = existing.get("id")
            self._request(
                "PATCH",
                f"/repos/{quote(self.repository, safe='/')}/issues/comments/{comment_id}",
                {"body": body},
            )
            return {"action": "updated", "url": existing.get("html_url")}
        created = self._request(
            "POST",
            f"/repos/{quote(self.repository, safe='/')}/issues/{pull_number}/comments",
            {"body": body},
        )
        return {"action": "created", "url": (created or {}).get("html_url")}


def write_step_summary(markdown: str, path: str | None = None) -> bool:
    summary_path = path or os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        LOGGER.debug("GITHUB_STEP_SUMMARY is not set; skipping job summary")
        return False
    try:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(markdown)
            if not markdown.endswith("\n"):
                handle.write("\n")
        return True
    except OSError as exc:
        LOGGER.warning("Could not write GitHub step summary: %s", exc)
        return False
