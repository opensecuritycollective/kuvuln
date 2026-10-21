"""CVSS v2/v3 base-score parsing without external dependencies."""

from __future__ import annotations

import math
import re
from typing import Any

from .models import severity_from_cvss

_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC = {"L": 0.77, "H": 0.44}
_V3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_V3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_V3_UI = {"N": 0.85, "R": 0.62}
_V3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_V2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_V2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_V2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_V2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}


def _roundup(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def parse_vector(vector: str) -> tuple[int, dict[str, str]] | None:
    """Parse a CVSS v2 or v3 vector into ``(version, metrics)``."""
    if not isinstance(vector, str):
        return None
    vector = vector.strip()
    match = re.match(r"^CVSS:([23])(?:\.\d)?/(.+)$", vector)
    if match:
        version = int(match.group(1))
        metrics = {}
        for item in match.group(2).split("/"):
            key, _, value = item.partition(":")
            if key and value:
                metrics[key.upper()] = value.upper()
        return version, metrics
    if vector.startswith("AV:") and "/" in vector:
        metrics = {}
        for item in vector.split("/"):
            key, _, value = item.partition(":")
            if key and value:
                metrics[key.upper()] = value.upper()
        return 2, metrics
    return None


def base_score(vector: str | None) -> float | None:
    """Compute the base score for a CVSS v2/v3 vector.

    CVSS v4 vectors are intentionally left unscored here; callers should use a
    numeric score supplied by the advisory when available.
    """
    parsed = parse_vector(vector or "")
    if not parsed:
        return None
    version, metrics = parsed
    if version == 2:
        return _v2_base(metrics)
    return _v3_base(metrics)


def _v3_base(metrics: dict[str, str]) -> float | None:
    try:
        av = _V3_AV[metrics["AV"]]
        ac = _V3_AC[metrics["AC"]]
        scope_changed = metrics.get("S") == "C"
        pr = (_V3_PR_CHANGED if scope_changed else _V3_PR_UNCHANGED)[metrics["PR"]]
        ui = _V3_UI[metrics["UI"]]
        c = _V3_CIA[metrics["C"]]
        i = _V3_CIA[metrics["I"]]
        a = _V3_CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def _v2_base(metrics: dict[str, str]) -> float | None:
    try:
        av = _V2_AV[metrics["AV"]]
        ac = _V2_AC[metrics["AC"]]
        au = _V2_AU[metrics["AU"]]
        c = _V2_CIA[metrics["C"]]
        i = _V2_CIA[metrics["I"]]
        a = _V2_CIA[metrics["A"]]
    except KeyError:
        return None
    impact = 10.41 * (1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a)))
    exploitability = 20.0 * av * ac * au
    if impact <= 0:
        return 0.0
    f_impact = 1.176 if impact > 0 else 1.0
    return round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact, 1)


def cvss_from_severity_entries(entries: Any) -> tuple[float | None, str | None, str]:
    """Extract the highest CVSS score/vector and severity from OSV severity data."""
    best_score: float | None = None
    best_vector: str | None = None
    best_severity = "UNKNOWN"
    if not isinstance(entries, list):
        return best_score, best_vector, best_severity

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("score")
        if raw is None:
            continue
        if isinstance(raw, (int, float)):
            score = float(raw)
            vector = None
        else:
            text = str(raw).strip()
            vector = text if text.upper().startswith(("CVSS:", "AV:")) else None
            score = None
            if vector:
                score = base_score(vector)
            else:
                try:
                    score = float(text)
                except ValueError:
                    score = None
        if score is None:
            continue
        severity = severity_from_cvss(score)
        if best_score is None or score > best_score:
            best_score = score
            best_vector = vector
            best_severity = severity
    return best_score, best_vector, best_severity


def normalize_cvss(value: Any) -> float | None:
    """Accept a number or vector and return a base score."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return base_score(str(value))
