"""Unit tests for scripts/parse_nuclei_jsonl.py, using examples/example_results.jsonl."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import parse_nuclei_jsonl
import pytest
from parse_nuclei_jsonl import NucleiJsonlError, digest_md

SKILL_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = SKILL_DIR / "examples" / "example_results.jsonl"
SCRIPT = SKILL_DIR / "scripts" / "parse_nuclei_jsonl.py"


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _write_lines(tmp_path: Path, lines: list[str]) -> Path:
    path = tmp_path / "results.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _finding(template_id: str, severity: str, matched_at: str = "http://x/") -> str:
    return json.dumps(
        {
            "template-id": template_id,
            "info": {"name": f"{template_id} name", "severity": severity},
            "matched-at": matched_at,
        }
    )


# --- committed fixture -------------------------------------------------------


def test_fixture_severity_groups_in_order() -> None:
    md = digest_md(EXAMPLE)
    assert md.index("## High (1)") < md.index("## Medium (1)") < md.index("## Info (1)")


def test_fixture_finding_contents() -> None:
    md = digest_md(EXAMPLE)
    assert "### Exposed Admin Panel (exposed-panel)" in md
    assert "- **Target**: http://192.162.34.1:8080" in md
    assert "- **Matched at**: `http://192.162.34.1:8080/admin/`" in md
    assert "- **Tags**: panel, exposure, admin" in md
    assert "matcher: status-code-200" in md
    assert "- **Description**: Admin panel is exposed without authentication" in md


def test_fixture_extractors_rendered() -> None:
    md = digest_md(EXAMPLE)
    assert "**Extracted**" in md
    assert "`server`: `Go http server`" in md
    assert "`uri`: `/plugins/servlet/oauth/users/icon-uri`" in md


def test_fixture_header_counts_findings() -> None:
    md = digest_md(EXAMPLE)
    assert "# nuclei findings digest — 3 finding(s)" in md


# --- synthetic documents -----------------------------------------------------


def test_empty_file() -> None:
    md = digest_md(Path("/dev/null"))
    assert "0 finding(s)" in md
    assert "No findings." in md


def test_unknown_severity_groups_last(tmp_path: Path) -> None:
    path = _write_lines(
        tmp_path,
        [
            _finding("a", "high", "http://a/"),
            _finding("b", "weird-sev", "http://b/"),
            _finding("c", "critical", "http://c/"),
        ],
    )
    md = digest_md(path)
    assert (
        md.index("## Critical (1)")
        < md.index("## High (1)")
        < md.index("## Unknown (1)")
    )


def test_missing_severity_defaults_to_unknown(tmp_path: Path) -> None:
    line = json.dumps(
        {"template-id": "x", "info": {"name": "n"}, "matched-at": "http://x/"}
    )
    md = digest_md(_write_lines(tmp_path, [line]))
    assert "## Unknown (1)" in md


def test_dedupe_by_template_and_matched_at(tmp_path: Path) -> None:
    path = _write_lines(
        tmp_path,
        [
            _finding("dup", "high", "http://a/"),
            _finding("dup", "high", "http://a/"),
            _finding("dup", "high", "http://b/"),
        ],
    )
    md = digest_md(path)
    assert "## High (2)" in md


def test_long_description_truncated(tmp_path: Path) -> None:
    long_desc = "word " * 300
    line = json.dumps(
        {
            "template-id": "x",
            "info": {"name": "n", "severity": "low", "description": long_desc},
            "matched-at": "http://x/",
        }
    )
    md = digest_md(_write_lines(tmp_path, [line]))
    assert "…" in md
    assert "## Low (1)" in md


def test_str_tags_handled(tmp_path: Path) -> None:
    line = json.dumps(
        {
            "template-id": "x",
            "info": {"name": "n", "severity": "low", "tags": "cve"},
            "matched-at": "http://x/",
        }
    )
    md = digest_md(_write_lines(tmp_path, [line]))
    assert "- **Tags**: cve" in md


def test_blank_lines_ignored(tmp_path: Path) -> None:
    path = _write_lines(tmp_path, ["", _finding("x", "info"), ""])
    assert "1 finding(s)" in digest_md(path)


def test_truncate_helper() -> None:
    assert parse_nuclei_jsonl._truncate("hello world") == "hello world"
    assert parse_nuclei_jsonl._truncate("a" * 10, 5) == "aaaa…"


# --- error paths -------------------------------------------------------------


def test_invalid_json_line(tmp_path: Path) -> None:
    path = _write_lines(tmp_path, [_finding("x", "info"), "{not json"])
    with pytest.raises(NucleiJsonlError, match="line 2"):
        digest_md(path)


def test_non_object_line(tmp_path: Path) -> None:
    path = _write_lines(tmp_path, ["[1, 2]"])
    with pytest.raises(NucleiJsonlError, match="not a JSON object"):
        digest_md(path)


# --- CLI ---------------------------------------------------------------------


def test_cli_stdout() -> None:
    r = _run_cli(str(EXAMPLE))
    assert r.returncode == 0, r.stderr
    assert "## High (1)" in r.stdout


def test_cli_writes_file(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "digest.md"
    r = _run_cli(str(EXAMPLE), "-o", str(out))
    assert r.returncode == 0, r.stderr
    assert "wrote" in r.stdout
    assert "## High (1)" in out.read_text(encoding="utf-8")


def test_cli_missing_file(tmp_path: Path) -> None:
    r = _run_cli(str(tmp_path / "nope.jsonl"))
    assert r.returncode == 1
    assert "file not found" in r.stderr


def test_cli_invalid_json_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{oops\n", encoding="utf-8")
    r = _run_cli(str(bad))
    assert r.returncode == 2
    assert "not valid JSON" in r.stderr
