"""Enrichment sources: EPSS, CISA KEV and end-of-life lifecycle data."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from typing import Any

from .cache import Cache
from .http import HttpClient, OfflineError
from .models import Finding

LOGGER = logging.getLogger("kuvuln.enrich")

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EOL_URL = "https://endoflife.date/api"

_EPS_BATCH = 100
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Static fallbacks keep the scanner useful when external APIs are unavailable.
KUBERNETES_EOL: dict[str, str] = {
    "1.28": "2024-10-28",
    "1.29": "2025-02-28",
    "1.30": "2025-07-15",
    "1.31": "2025-11-11",
    "1.32": "2026-02-28",
    "1.33": "2026-06-28",
    "1.34": "2026-10-27",
    "1.35": "2027-02-28",
    "1.36": "2027-06-28",
    "1.37": "2027-10-28",
}
GO_EOL: dict[str, str] = {
    "1.18": "2023-02-01",
    "1.19": "2023-09-06",
    "1.20": "2024-02-06",
    "1.21": "2024-08-13",
    "1.22": "2025-02-11",
    "1.23": "2025-08-12",
    "1.24": "2026-02-10",
    "1.25": "2026-08-19",
}


def cve_identifiers(findings: Iterable[Finding]) -> list[str]:
    """Collect CVE ids from finding identifiers and aliases."""
    cves: set[str] = set()
    for finding in findings:
        for value in finding.all_identifiers():
            if _CVE_RE.match(value.strip()):
                cves.add(value.strip().upper())
    return sorted(cves)


class EpssClient:
    def __init__(
        self,
        http: HttpClient,
        cache: Cache,
        timeout: float = 20,
        retries: int = 2,
        ttl_hours: float = 24,
    ) -> None:
        self.http = http
        self.cache = cache
        self.timeout = timeout
        self.retries = retries
        self.ttl_hours = ttl_hours
        self._index: dict[str, dict[str, Any]] | None = None

    def _load_index(self) -> dict[str, dict[str, Any]]:
        if self._index is not None:
            return self._index
        cached = self.cache.get("enrichment:epss:index", ttl_hours=self.ttl_hours)
        self._index = cached if isinstance(cached, dict) else {}
        return self._index

    def scores(self, cves: Iterable[str]) -> dict[str, dict[str, Any]]:
        requested = sorted({cve.strip().upper() for cve in cves if cve.strip()})
        index = self._load_index()
        missing = [cve for cve in requested if cve not in index]
        if missing:
            for start in range(0, len(missing), _EPS_BATCH):
                chunk = missing[start : start + _EPS_BATCH]
                fetched = self._fetch(chunk)
                index.update(fetched)
                self._index = index
            self.cache.set("enrichment:epss:index", index)
        return {cve: index[cve] for cve in requested if cve in index}

    def _fetch(self, chunk: list[str]) -> dict[str, dict[str, Any]]:
        params = "&".join([f"cve={cve}" for cve in chunk])
        url = f"{EPSS_URL}?{params}"
        try:
            payload = self.http.json(
                "GET", url, timeout=self.timeout, retries=self.retries
            )
        except OfflineError:
            return {}
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("EPSS query failed: %s", exc)
            return {}
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return {}
        out: dict[str, dict[str, Any]] = {}
        for entry in data:
            if not isinstance(entry, dict) or not entry.get("cve"):
                continue
            try:
                out[str(entry["cve"]).upper()] = {
                    "score": float(entry.get("epss") or 0.0),
                    "percentile": float(entry.get("percentile") or 0.0),
                    "date": entry.get("date"),
                }
            except (TypeError, ValueError):
                continue
        return out


class KevClient:
    def __init__(
        self,
        http: HttpClient,
        cache: Cache,
        timeout: float = 30,
        retries: int = 2,
        ttl_hours: float = 12,
    ) -> None:
        self.http = http
        self.cache = cache
        self.timeout = timeout
        self.retries = retries
        self.ttl_hours = ttl_hours
        self._catalog: set[str] | None = None

    def catalog(self) -> set[str]:
        if self._catalog is not None:
            return self._catalog
        cached = self.cache.get("enrichment:kev:catalog", ttl_hours=self.ttl_hours)
        if isinstance(cached, list):
            self._catalog = {str(item).upper() for item in cached if item}
            return self._catalog
        try:
            payload = self.http.json(
                "GET", KEV_URL, timeout=self.timeout, retries=self.retries
            )
        except OfflineError:
            return set()
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("KEV catalog fetch failed: %s", exc)
            return set()
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        catalog = {
            str(item.get("cveID")).upper()
            for item in vulnerabilities or []
            if isinstance(item, dict) and item.get("cveID")
        }
        self._catalog = catalog
        self.cache.set("enrichment:kev:catalog", sorted(catalog))
        return catalog

    def contains(self, cve: str) -> bool:
        return cve.upper() in self.catalog()


@dataclass
class LifecycleStatus:
    eol: bool
    eol_date: date | None
    cycle: str
    latest: str | None
    source: str


class LifecycleClient:
    def __init__(
        self,
        http: HttpClient,
        cache: Cache,
        timeout: float = 20,
        retries: int = 2,
        ttl_hours: float = 24,
        products: Iterable[str] = ("kubernetes", "go"),
    ) -> None:
        self.http = http
        self.cache = cache if cache is not None else Cache()
        self.timeout = timeout
        self.retries = retries
        self.ttl_hours = ttl_hours
        self.products = {product.lower() for product in products}

    def _fallback(self, product: str) -> dict[str, str]:
        if product == "kubernetes":
            return KUBERNETES_EOL
        if product == "go":
            return GO_EOL
        return {}

    def _data(self, product: str) -> list[dict[str, Any]]:
        cached = self.cache.get(f"enrichment:eol:{product}", ttl_hours=self.ttl_hours)
        if isinstance(cached, list):
            return [item for item in cached if isinstance(item, dict)]
        if not self.products or product not in self.products:
            return []
        if self.http is None:
            return []
        try:
            payload = self.http.json(
                "GET",
                f"{EOL_URL}/{product}.json",
                timeout=self.timeout,
                retries=self.retries,
            )
        except OfflineError:
            return []
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Lifecycle lookup failed for %s: %s", product, exc)
            return []
        if isinstance(payload, list):
            self.cache.set(f"enrichment:eol:{product}", payload)
            return [item for item in payload if isinstance(item, dict)]
        return []

    def status(self, product: str, version: str, today: date | None = None) -> LifecycleStatus | None:
        product = product.lower()
        cycle = _cycle(version)
        if not cycle:
            return None
        today = today or date.today()
        entries = self._data(product)
        entry = next((item for item in entries if str(item.get("cycle")) == cycle), None)
        source = "endoflife.date"
        if entry is None:
            fallback = self._fallback(product)
            eol_date = fallback.get(cycle)
            if not eol_date:
                return None
            entry = {
                "cycle": cycle,
                "eol": eol_date,
                "latest": None,
                "source": "fallback",
            }
            source = "static-fallback"
        raw_eol = entry.get("eol")
        if isinstance(raw_eol, bool):
            eol = raw_eol
            eol_date = today if eol else None
        elif isinstance(raw_eol, str):
            from .utils import parse_date

            eol_date = parse_date(raw_eol)
            eol = eol_date is not None and eol_date <= today
        else:
            eol_date = None
            eol = False
        return LifecycleStatus(
            eol=eol,
            eol_date=eol_date,
            cycle=cycle,
            latest=str(entry.get("latest")) if entry.get("latest") else None,
            source=source,
        )


def _cycle(version: str) -> str | None:
    text = str(version).strip().lstrip("vV")
    match = re.match(r"^(\d+\.\d+)(?:[.-]\d+)?", text)
    return match.group(1) if match else None


def enrich_findings(
    findings: list[Finding],
    config,
    epss_client: EpssClient | None,
    kev_client: KevClient | None,
) -> int:
    """Attach EPSS/KEV data to findings. Returns the number of CVEs enriched."""
    if not findings:
        return 0
    cves = cve_identifiers(findings)
    if not cves:
        return 0
    epss_index: dict[str, dict[str, Any]] = {}
    if epss_client is not None and config.get("enrichment.epss", True):
        epss_index = epss_client.scores(cves)
    kev_catalog = (
        kev_client.catalog() if kev_client is not None and config.get("enrichment.kev", True) else set()
    )
    enriched = 0
    for finding in findings:
        for value in finding.all_identifiers():
            if not _CVE_RE.match(value.strip()):
                continue
            cve = value.strip().upper()
            score = epss_index.get(cve)
            if score:
                finding.epss = score.get("score")
                finding.epss_percentile = score.get("percentile")
            if kev_catalog and cve in kev_catalog:
                finding.kev = True
            enriched += 1
            break
    return enriched
