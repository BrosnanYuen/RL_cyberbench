#!/usr/bin/env python3
"""OWASP ZAP alerts/report JSON -> markdown digest for LLM agents.

Reads either the ZAP API ``core/view/alerts`` JSON (``{"alerts": [...]}``) or
a ``traditional-json`` report (``{"site": [{"alerts": [...]}]}``) and renders
a compact markdown digest: one section per risk level (High -> Medium -> Low
-> Informational), alerts deduplicated by (name, first url), each showing
urls, CWE/WASC ids, a truncated description + solution, and the top
instances' request/evidence details. stdlib only.

Usage: parse_zap_alerts.py <alerts.json> [-o digest.md]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RISK_ORDER = ["High", "Medium", "Low", "Informational"]
DESC_LIMIT = 500
SOLUTION_LIMIT = 300
MAX_URLS = 6
MAX_INSTANCES = 4


class ZapAlertsError(ValueError):
    """Raised when the input is not a parseable ZAP alerts document."""


def _truncate(text: str, limit: int) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _as_str(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return ""
    return str(value)


def _alert(record: dict) -> dict:
    name = _as_str(record.get("name") or record.get("alert") or "unnamed alert")
    risk = _as_str(record.get("risk") or "Informational").strip()
    if risk not in RISK_ORDER:
        risk = "Informational"

    urls: list[str] = []
    for url in record.get("urls") or []:
        if isinstance(url, dict):
            urls.append(_as_str(url.get("url") or url.get("uri") or ""))
        else:
            urls.append(_as_str(url))
    if record.get("url"):
        urls.insert(0, _as_str(record["url"]))
    dedup_urls: list[str] = []
    for url in urls:
        if url and url not in dedup_urls:
            dedup_urls.append(url)
    urls = dedup_urls

    instances: list[dict[str, str]] = []
    for inst in record.get("instances") or []:
        if not isinstance(inst, dict):
            continue
        instances.append(
            {
                k: _as_str(inst.get(k))
                for k in ("uri", "url", "method", "param", "attack", "evidence")
            }
        )
    if record.get("uri"):
        instances.insert(
            0,
            {
                "uri": _as_str(record["uri"]),
                "method": _as_str(record.get("method")),
                "param": _as_str(record.get("param")),
                "attack": _as_str(record.get("attack")),
                "evidence": _as_str(record.get("evidence")),
            },
        )

    return {
        "name": name,
        "risk": risk,
        "confidence": _as_str(record.get("confidence")),
        "cwe": _as_str(record.get("cweId")),
        "wasc": _as_str(record.get("wascId")),
        "description": _as_str(record.get("description")),
        "solution": _as_str(record.get("solution")),
        "urls": urls,
        "instances": instances,
    }


def _collect_alerts(doc: dict) -> list[dict]:
    if "alerts" in doc and isinstance(doc["alerts"], list):
        return [_alert(a) for a in doc["alerts"] if isinstance(a, dict)]
    if "site" in doc and isinstance(doc["site"], list):
        alerts: list[dict] = []
        for site in doc["site"]:
            if isinstance(site, dict):
                for a in site.get("alerts") or []:
                    if isinstance(a, dict):
                        alerts.append(_alert(a))
        return alerts
    msg = "not a ZAP alerts document (no 'alerts' list and no 'site' list)"
    raise ZapAlertsError(msg)


def digest_md(json_path: Path) -> str:
    """Render *json_path* (ZAP alerts JSON or traditional-json report) as markdown."""
    try:
        doc = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        msg = f"invalid JSON: {e}"
        raise ZapAlertsError(msg) from e
    if not isinstance(doc, dict):
        msg = "not a JSON object"
        raise ZapAlertsError(msg)

    alerts = _collect_alerts(doc)
    dedup: dict[tuple[str, str], dict] = {}
    for a in alerts:
        key = (a["name"], a["urls"][0] if a["urls"] else "")
        dedup[key] = a

    lines = [f"# ZAP alerts digest — {len(dedup)} alert(s)", ""]
    if not dedup:
        lines += ["No alerts.", ""]
        return "\n".join(lines).rstrip() + "\n"

    by_risk: dict[str, list[dict]] = {}
    for a in dedup.values():
        by_risk.setdefault(a["risk"], []).append(a)

    for risk in RISK_ORDER:
        group = by_risk.get(risk)
        if not group:
            continue
        lines += [f"## {risk} ({len(group)})", ""]
        for a in group:
            lines.append(f"### {a['name']}")
            meta = [f"risk: {a['risk']}"]
            if a["confidence"]:
                meta.append(f"confidence: {a['confidence']}")
            if a["cwe"] and a["cwe"] != "0":
                meta.append(f"CWE-{a['cwe']}")
            if a["wasc"] and a["wasc"] != "0":
                meta.append(f"WASC-{a['wasc']}")
            lines += ["", f"- **{' · '.join(meta)}**"]
            for url in a["urls"][:MAX_URLS]:
                lines += [f"- **URL**: `{url}`"]
            if a["instances"]:
                lines += ["- **Instances**:"]
                for inst in a["instances"][:MAX_INSTANCES]:
                    bits = [
                        f"`{inst.get('method') or '?'}` {inst.get('uri') or inst.get('url') or ''}".strip()
                    ]
                    if inst.get("param"):
                        bits.append(f"param=`{inst['param']}`")
                    if inst.get("attack"):
                        bits.append(f"attack=`{_truncate(inst['attack'], 120)}`")
                    if inst.get("evidence"):
                        bits.append(f"evidence=`{_truncate(inst['evidence'], 120)}`")
                    lines += [f"  - {' · '.join(bits)}"]
            if a["description"]:
                lines += [
                    f"- **Description**: {_truncate(a['description'], DESC_LIMIT)}"
                ]
            if a["solution"]:
                lines += [f"- **Solution**: {_truncate(a['solution'], SOLUTION_LIMIT)}"]
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="parse_zap_alerts",
        description="Convert OWASP ZAP alerts/report JSON to a markdown digest.",
    )
    parser.add_argument(
        "json", type=Path, help="ZAP alerts JSON (API) or traditional-json report"
    )
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="write digest here (default: stdout)",
    )
    opts = parser.parse_args(argv)

    if not opts.json.is_file() and str(opts.json) != "/dev/stdin":
        print(f"parse_zap_alerts: file not found: {opts.json}", file=sys.stderr)
        return 1
    try:
        md = digest_md(opts.json)
    except ZapAlertsError as e:
        print(f"parse_zap_alerts: {e}", file=sys.stderr)
        return 2

    if opts.out is None:
        sys.stdout.write(md)
    else:
        opts.out.parent.mkdir(parents=True, exist_ok=True)
        opts.out.write_text(md, encoding="utf-8")
        print(f"wrote {opts.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
