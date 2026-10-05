#!/usr/bin/env python3
"""nuclei JSONL (-jle output) -> markdown digest for LLM agents.

Reads a nuclei JSONL(ines) results file and renders a compact markdown
digest: one section per severity (critical -> unknown), findings deduplicated
by (template-id, matched-at), each showing target, matcher, tags, extracted
values and a truncated description. stdlib only.

Usage: parse_nuclei_jsonl.py <results.jsonl> [-o digest.md]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
DESC_LIMIT = 600


class NucleiJsonlError(ValueError):
    """Raised when the input is not a parseable nuclei JSONL file."""


def _truncate(text: str, limit: int = DESC_LIMIT) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _finding(record: dict) -> dict:
    info = record.get("info") or {}
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    severity = str(info.get("severity") or "unknown").lower()
    if severity not in SEVERITY_ORDER:
        severity = "unknown"
    return {
        "id": str(record.get("template-id") or "unknown-template"),
        "name": str(info.get("name") or "unnamed template"),
        "severity": severity,
        "description": str(info.get("description") or ""),
        "tags": [str(t) for t in tags],
        "matched_at": str(record.get("matched-at") or ""),
        "host": str(record.get("host") or ""),
        "ip": str(record.get("ip") or ""),
        "matcher": str(record.get("matcher-name") or ""),
        "type": str(record.get("type") or ""),
        "extractors": {
            str(k): str(v)
            for k, v in (record.get("extractors") or {}).items()
            if v is not None
        },
    }


def _finding_md(f: dict) -> list[str]:
    lines = [f"### {f['name']} ({f['id']})", ""]
    target = f["host"] or f["ip"]
    if target:
        lines += [f"- **Target**: {target}"]
    if f["matched_at"]:
        lines += [f"- **Matched at**: `{f['matched_at']}`"]
    meta = []
    if f["type"]:
        meta.append(f["type"])
    if f["matcher"]:
        meta.append(f"matcher: {f['matcher']}")
    if meta:
        lines += [f"- **Check**: {' · '.join(meta)}"]
    if f["tags"]:
        lines += [f"- **Tags**: {', '.join(f['tags'])}"]
    if f["extractors"]:
        lines += ["- **Extracted**:"]
        for key, value in f["extractors"].items():
            lines += [f"  - `{key}`: `{_truncate(value, 200)}`"]
    if f["description"]:
        lines += [f"- **Description**: {_truncate(f['description'])}"]
    lines.append("")
    return lines


def digest_md(jsonl_path: Path) -> str:
    """Render *jsonl_path* (nuclei -jle output) as a markdown digest string."""
    findings: dict[tuple[str, str], dict] = {}
    with jsonl_path.open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                msg = f"line {lineno} is not valid JSON: {e}"
                raise NucleiJsonlError(msg) from e
            if not isinstance(record, dict):
                msg = f"line {lineno} is not a JSON object"
                raise NucleiJsonlError(msg)
            f = _finding(record)
            findings[(f["id"], f["matched_at"])] = f

    lines = [f"# nuclei findings digest — {len(findings)} finding(s)", ""]
    if not findings:
        lines += ["No findings.", ""]
        return "\n".join(lines).rstrip() + "\n"

    by_severity: dict[str, list[dict]] = {}
    for f in findings.values():
        by_severity.setdefault(f["severity"], []).append(f)

    for severity in SEVERITY_ORDER:
        group = by_severity.get(severity)
        if not group:
            continue
        lines += [f"## {severity.capitalize()} ({len(group)})", ""]
        for f in group:
            lines += _finding_md(f)

    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="parse_nuclei_jsonl",
        description="Convert nuclei -jle JSONL output to a markdown digest.",
    )
    parser.add_argument("jsonl", type=Path, help="nuclei JSONL file (-jle output)")
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="write digest here (default: stdout)",
    )
    opts = parser.parse_args(argv)

    if not opts.jsonl.is_file():
        print(f"parse_nuclei_jsonl: file not found: {opts.jsonl}", file=sys.stderr)
        return 1
    try:
        md = digest_md(opts.jsonl)
    except NucleiJsonlError as e:
        print(f"parse_nuclei_jsonl: {e}", file=sys.stderr)
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
