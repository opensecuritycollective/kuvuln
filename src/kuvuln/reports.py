"""Report rendering: Markdown, JSON, HTML and step summaries."""

from __future__ import annotations

import html
from typing import Any

from . import __version__
from .models import (
    CATEGORY_LABELS,
    SEVERITIES,
    Finding,
    category_counts,
    finding_sort_key,
)
from .policy import PolicyResult, score
from .utils import iso_now

MARKER = "<!-- kuvuln-report:v3 -->"
_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
    "UNKNOWN": "⚪",
}
_CATEGORY_ORDER = [
    "kubernetes",
    "rbac",
    "network",
    "supply-chain",
    "container",
    "sca",
    "secret",
    "sast",
    "iac",
    "license",
    "lifecycle",
    "ci",
    "unknown",
]


def render_markdown(
    findings: list[Finding],
    all_findings: list[Finding],
    policy: PolicyResult,
    config: Any,
    metadata: dict[str, Any],
    dependencies: list[Any],
    suppressed: list[dict[str, Any]],
    compliance: dict[str, int],
) -> str:
    max_details = int(config.get("notifications.max_findings_in_comment", 25))
    for details_limit in (max_details, 50, 20, 5):
        text = _build_markdown(
            findings,
            all_findings,
            policy,
            config,
            metadata,
            dependencies,
            suppressed,
            compliance,
            details_limit,
        )
        if len(text) <= 60_000:
            return text
    return text[:60_000]


def _build_markdown(
    findings: list[Finding],
    all_findings: list[Finding],
    policy: PolicyResult,
    config: Any,
    metadata: dict[str, Any],
    dependencies: list[Any],
    suppressed: list[dict[str, Any]],
    compliance: dict[str, int],
    details_limit: int,
) -> str:
    lines: list[str] = [MARKER]
    lines.append("# 🛡️ KuVuln Security Report")
    lines.append("")
    status = "✅ Passed" if policy.passed else "❌ Policy gate failed"
    lines.append(f"**Policy status:** {status} ")
    lines.append(f"**KuVuln score:** {score(findings) if findings else 100.0}/100 ")
    commit = metadata.get("commit_short") or metadata.get("commit") or "unknown"
    branch = metadata.get("branch") or "unknown"
    lines.append(f"**Commit:** `{commit}` on `{branch}` ")
    lines.append(f"**Generated:** {metadata.get('generated_at', iso_now())}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Critical | High | Medium | Low | Info | Total |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    counts = category_counts(all_findings)
    totals = {severity: 0 for severity in SEVERITIES}
    for category in _CATEGORY_ORDER:
        if category not in counts:
            continue
        bucket = counts[category]
        total = sum(bucket.values())
        for severity in SEVERITIES:
            totals[severity] += bucket[severity]
        lines.append(
            f"| {CATEGORY_LABELS.get(category, category)} | "
            f"{bucket['CRITICAL']} | {bucket['HIGH']} | {bucket['MEDIUM']} | "
            f"{bucket['LOW']} | {bucket['INFO']} | {total} |"
        )
    total_all = sum(totals.values())
    lines.append(
        f"| **Total** | **{totals['CRITICAL']}** | **{totals['HIGH']}** | "
        f"**{totals['MEDIUM']}** | **{totals['LOW']}** | **{totals['INFO']}** | "
        f"**{total_all}** |"
    )
    lines.append("")
    lines.append(
        f"- **Dependencies analyzed:** {len(dependencies)} "
        f"(SCA across Go, npm, PyPI and more)"
    )
    lines.append(f"- **CISA KEV (known exploited):** {policy.kev_count}")
    epss_threshold = float(config.get("settings.fail_on_epss", 0.0) or 0.0)
    epss_label = f"{epss_threshold}" if epss_threshold > 0 else "disabled"
    lines.append(
        f"- **EPSS ≥ {epss_label}:** {policy.epss_count}"
    )
    lines.append(f"- **Fixable SCA findings:** {policy.fixable_count}")
    if suppressed:
        lines.append(f"- **Suppressed by policy/baseline:** {len(suppressed)}")
    lines.append("")

    if not policy.passed:
        lines.append("## 🚨 Policy violations")
        lines.append("")
        for reason in policy.reasons:
            lines.append(f"- {reason}")
        lines.append("")

    if compliance:
        lines.append("## Compliance coverage")
        lines.append("")
        lines.append("| Standard | Mapped findings |")
        lines.append("|---|---:|")
        for standard, count in sorted(compliance.items()):
            lines.append(f"| {standard} | {count} |")
        lines.append("")

    top = sorted(findings, key=finding_sort_key)[:details_limit]
    lines.append(f"## Top findings ({len(top)})")
    lines.append("")
    if top:
        lines.append(
            "| Sev | Risk | Category | Finding | Package | Fixed | Location |"
        )
        lines.append("|---|---|---|---|---|---|---|")
        for finding in top:
            lines.append(_markdown_row(finding))
        lines.append("")
    else:
        lines.append("_No findings to report._")
        lines.append("")

    grouped = _group_by_category(findings)
    lines.append("<details>")
    lines.append("<summary>Full finding list</summary>")
    lines.append("")
    for category in _CATEGORY_ORDER:
        category_findings = grouped.get(category)
        if not category_findings:
            continue
        lines.append(f"### {CATEGORY_LABELS.get(category, category)} ({len(category_findings)})")
        lines.append("")
        for finding in sorted(category_findings, key=finding_sort_key)[:details_limit]:
            lines.append(
                f"- **{_SEVERITY_EMOJI.get(finding.severity, '⚪')} {finding.severity}** "
                f"`{finding.rule_id}` {escape_md(finding.title)} "
                f"— {_location_label(finding)}"
            )
            if finding.kev:
                lines.append("  - ⚠️ Listed in the CISA KEV catalog")
            if finding.reachable:
                lines.append("  - 🎯 Reachable in code (govulncheck)")
        lines.append("")
    lines.append("</details>")
    lines.append("")

    lines.append("## What to do next")
    lines.append("")
    lines.append("1. Review the **Security** tab for line-level annotations.")
    lines.append("2. Upgrade dependencies with a published fixed version first.")
    lines.append("3. Fix Kubernetes workload hardening (PSS restricted) and RBAC.")
    lines.append("4. Re-run `kuvuln scan --offline` locally while iterating.")
    lines.append("")
    lines.append(
        f"_Report generated by KuVuln {__version__}. Full JSON, HTML and SARIF "
        "reports are attached to the workflow run._"
    )
    return "\n".join(lines) + "\n"


def render_step_summary(
    findings: list[Finding],
    all_findings: list[Finding],
    policy: PolicyResult,
    config: Any,
    metadata: dict[str, Any],
    dependencies: list[Any],
) -> str:
    counts = category_counts(all_findings)
    totals = {severity: 0 for severity in SEVERITIES}
    for bucket in counts.values():
        for severity in SEVERITIES:
            totals[severity] += bucket[severity]
    status = "✅ Passed" if policy.passed else "❌ Policy gate failed"
    lines = [
        MARKER,
        f"## 🛡️ KuVuln — {status}",
        "",
        (
            f"**Score:** {score(findings) if findings else 100.0}/100 · "
            f"**CRITICAL:** {totals['CRITICAL']} · **HIGH:** {totals['HIGH']} · "
            f"**MEDIUM:** {totals['MEDIUM']} · **LOW:** {totals['LOW']} · "
            f"**Dependencies:** {len(dependencies)} · **KEV:** {policy.kev_count}"
        ),
        "",
    ]
    if not policy.passed:
        lines.append("### Policy violations")
        for reason in policy.reasons:
            lines.append(f"- {reason}")
        lines.append("")
    top = sorted(findings, key=finding_sort_key)[:15]
    if top:
        lines.append("| Sev | Category | Finding | Location |")
        lines.append("|---|---|---|---|")
        for finding in top:
            lines.append(_markdown_row(finding))
        lines.append("")
    return "\n".join(lines) + "\n"


def _markdown_row(finding: Finding) -> str:
    package = escape_md(finding.package_label) if finding.package_label else "—"
    fixed = escape_md(finding.fixed_version) if finding.fixed_version else "—"
    return (
        f"| {_SEVERITY_EMOJI.get(finding.severity, '⚪')} {finding.severity} "
        f"| {finding.risk_score:.1f} | {CATEGORY_LABELS.get(finding.category, finding.category)} "
        f"| {escape_md(finding.title)} | {package} | {fixed} "
        f"| {_location_label(finding)} |"
    )


def _location_label(finding: Finding) -> str:
    if not finding.location.path:
        return "—"
    line = finding.location.start_line
    return f"`{escape_md(finding.location.path)}`" + (f":{line}" if line else "")


def _group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)
    return grouped


def escape_md(value: Any) -> str:
    text = " ".join(str(value or "").split())
    return text.replace("|", "\\|").replace("`", "\\`")


def render_json(
    findings: list[Finding],
    all_findings: list[Finding],
    policy: PolicyResult,
    config: Any,
    metadata: dict[str, Any],
    dependencies: list[Any],
    suppressed: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 3,
        "tool": {"name": "KuVuln", "version": __version__},
        "generated_at": metadata.get("generated_at", iso_now()),
        "metadata": metadata,
        "config": config.summary(),
        "summary": {
            "total": len(all_findings),
            "policy_passed": policy.passed,
            "policy_reasons": policy.reasons,
            "counts_by_severity": policy.counts_by_severity,
            "counts_by_category": policy.counts_by_category,
            "kev_count": policy.kev_count,
            "epss_count": policy.epss_count,
            "fixable_count": policy.fixable_count,
            "suppressed_count": len(suppressed),
            "score": score(all_findings),
        },
        "tools": tools,
        "findings": [finding.to_dict() for finding in sorted(all_findings, key=finding_sort_key)],
        "dependencies": [dependency.to_dict() for dependency in dependencies],
        "suppressed": suppressed,
    }


def render_html(
    findings: list[Finding],
    all_findings: list[Finding],
    policy: PolicyResult,
    config: Any,
    metadata: dict[str, Any],
    dependencies: list[Any],
    suppressed: list[dict[str, Any]],
) -> str:
    title = "KuVuln Security Report"
    score_value = score(all_findings)
    counts = category_counts(all_findings)
    rows: list[str] = []
    for finding in sorted(all_findings, key=finding_sort_key):
        rows.append(
            "<tr data-severity=\"{severity}\" data-category=\"{category}\" data-text=\"{text}\">"
            "<td>{sev}</td><td>{risk}</td><td>{cat}</td><td>{title}</td>"
            "<td>{package}</td><td>{fixed}</td><td>{location}</td>"
            "<td>{sources}</td></tr>".format(
                severity=html.escape(finding.severity),
                category=html.escape(finding.category),
                text=html.escape(
                    f"{finding.title} {finding.description} {finding.rule_id} {finding.package or ''}"
                ).lower(),
                sev=html.escape(finding.severity),
                risk=f"{finding.risk_score:.1f}",
                cat=html.escape(CATEGORY_LABELS.get(finding.category, finding.category)),
                title=html.escape(finding.title),
                package=html.escape(finding.package_label or "—"),
                fixed=html.escape(finding.fixed_version or "—"),
                location=html.escape(finding.location.label()),
                sources=html.escape(
                    ", ".join(finding.properties.get("reported_by", []) or [finding.source])
                ),
            )
        )
    category_cards = "".join(
        f'<div class="card"><div class="card-title">{html.escape(label)}</div>'
        f'<div class="card-value">{sum((counts.get(key) or {}).values())}</div></div>'
        for key, label in CATEGORY_LABELS.items()
        if key in counts
    )
    reasons = "".join(
        f"<li>{html.escape(reason)}</li>" for reason in policy.reasons
    )
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root{{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--card:#161b22;--border:#30363d;--red:#f85149;--orange:#d29922;--yellow:#e3b341;--blue:#388bfd}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif}}
main{{max-width:1400px;margin:0 auto;padding:32px}}h1{{margin:0 0 8px}}h2{{border-bottom:1px solid var(--border);padding-bottom:8px}}
.meta{{color:var(--muted);margin-bottom:24px}} .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px}}.card-title{{color:var(--muted);font-size:12px;text-transform:uppercase}}.card-value{{font-size:26px;font-weight:700}}
.status{{padding:12px 16px;border-radius:8px;background:var(--card);border:1px solid var(--border);margin-bottom:16px}}
.status.fail{{border-left:4px solid var(--red)}}.status.pass{{border-left:4px solid #3fb950}}
table{{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}}th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
th{{position:sticky;top:0;background:var(--bg)}}tr[data-severity="CRITICAL"] td:first-child{{color:var(--red);font-weight:700}}tr[data-severity="HIGH"] td:first-child{{color:var(--orange);font-weight:700}}tr[data-severity="MEDIUM"] td:first-child{{color:var(--yellow)}}
.filters{{display:flex;gap:8px;margin:12px 0;flex-wrap:wrap}}select,input{{background:var(--card);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:8px}}
.score{{font-size:32px;font-weight:800}}
</style></head><body><main>
<h1>🛡️ {html.escape(title)}</h1>
<div class="meta">{html.escape(str(metadata.get('commit_short','')))} · {html.escape(str(metadata.get('branch','')))} · {html.escape(str(metadata.get('generated_at','')))} · KuVuln {html.escape(__version__)}</div>
<div class="status {'fail' if not policy.passed else 'pass'}"><strong>{'Policy gate failed' if not policy.passed else 'Policy gate passed'}</strong> — score {score_value}/100, {len(all_findings)} findings, {len(dependencies)} dependencies, {policy.kev_count} KEV.</div>
<div class="cards"><div class="card"><div class="card-title">Score</div><div class="card-value">{score_value}</div></div>{category_cards}</div>
{f'<h2>Policy violations</h2><ul>{reasons}</ul>' if reasons else ''}
<div class="filters"><select id="severity"><option value="">All severities</option>{''.join(f'<option>{s}</option>' for s in SEVERITIES)}</select>
<select id="category"><option value="">All categories</option>{''.join(f'<option value="{html.escape(c)}">{html.escape(CATEGORY_LABELS.get(c,c))}</option>' for c in _CATEGORY_ORDER if c in counts)}</select>
<input id="search" placeholder="Search findings…" size="40"></div>
<table><thead><tr><th>Severity</th><th>Risk</th><th>Category</th><th>Finding</th><th>Package</th><th>Fixed</th><th>Location</th><th>Sources</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<script>
const severity=document.getElementById('severity'),category=document.getElementById('category'),search=document.getElementById('search');
function apply(){{const s=severity.value,c=category.value,q=search.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(row=>{{const ok=(!s||row.dataset.severity===s)&&(!c||row.dataset.category===c)&&(!q||row.dataset.text.includes(q));row.style.display=ok?'':'none';}})}}
[severity,category].forEach(el=>el.addEventListener('change',apply));search.addEventListener('input',apply);
</script>
</main></body></html>"""
    return body
