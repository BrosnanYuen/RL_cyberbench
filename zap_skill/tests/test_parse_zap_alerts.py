"""Unit tests for scripts/parse_zap_alerts.py, using examples/example_alerts.json."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from parse_zap_alerts import RISK_ORDER, ZapAlertsError, digest_md

SKILL_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = SKILL_DIR / "examples" / "example_alerts.json"
SCRIPT = SKILL_DIR / "scripts" / "parse_zap_alerts.py"


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _write_json(tmp_path: Path, doc: dict) -> Path:
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _api_alert(name: str, risk: str, url: str = "http://x/") -> dict:
    return {
        "name": name,
        "alert": name,
        "risk": risk,
        "confidence": "Medium",
        "url": url,
        "urls": [url],
    }


def _api_doc(*alerts: dict) -> dict:
    return {"alerts": list(alerts)}


# --- committed fixture -------------------------------------------------------


def test_fixture_risk_groups_in_order() -> None:
    md = digest_md(EXAMPLE)
    assert md.index("## High (1)") < md.index("## Medium (1)") < md.index("## Low (1)")


def test_fixture_alert_contents() -> None:
    md = digest_md(EXAMPLE)
    assert "### SQL Injection" in md
    assert "CWE-89" in md
    assert "WASC-19" in md
    assert "param=`q`" in md
    assert "attack=`1' OR 1=1`" in md
    assert "## Low (1)" in md


def test_fixture_description_and_solution() -> None:
    md = digest_md(EXAMPLE)
    assert "**Description**: SQL injection may be possible." in md
    assert "**Solution**: Do not construct SQL queries" in md


def test_fixture_header_counts() -> None:
    assert "# ZAP alerts digest — 3 alert(s)" in digest_md(EXAMPLE)


# --- synthetic documents -----------------------------------------------------


def test_api_shape_works(tmp_path: Path) -> None:
    md = digest_md(
        _write_json(tmp_path, _api_doc(_api_alert("XSS", "High", "http://a/")))
    )
    assert "## High (1)" in md
    assert "### XSS" in md


def test_empty_alerts(tmp_path: Path) -> None:
    md = digest_md(_write_json(tmp_path, _api_doc()))
    assert "0 alert(s)" in md
    assert "No alerts." in md


def test_unknown_risk_defaults_to_informational(tmp_path: Path) -> None:
    md = digest_md(_write_json(tmp_path, _api_doc(_api_alert("odd", "Extreme"))))
    assert "## Informational (1)" in md


def test_dedupe_by_name_and_url(tmp_path: Path) -> None:
    doc = _api_doc(
        _api_alert("dup", "High", "http://a/"),
        _api_alert("dup", "High", "http://a/"),
        _api_alert("dup", "High", "http://b/"),
    )
    md = digest_md(_write_json(tmp_path, doc))
    assert "## High (2)" in md


def test_instances_and_evidence(tmp_path: Path) -> None:
    alert = {
        "name": "n",
        "risk": "Medium",
        "instances": [
            {
                "uri": "http://x/?p=1",
                "method": "GET",
                "param": "p",
                "attack": "a",
                "evidence": "e",
            }
        ],
    }
    md = digest_md(_write_json(tmp_path, _api_doc(alert)))
    assert "`GET` http://x/?p=1" in md
    assert "param=`p`" in md
    assert "evidence=`e`" in md


def test_long_text_truncated(tmp_path: Path) -> None:
    alert = _api_alert("n", "Low")
    alert["description"] = "word " * 400
    md = digest_md(_write_json(tmp_path, _api_doc(alert)))
    assert "…" in md


def test_risk_order_constant() -> None:
    assert RISK_ORDER == ["High", "Medium", "Low", "Informational"]


# --- error paths -------------------------------------------------------------


def test_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    with pytest.raises(ZapAlertsError, match="invalid JSON"):
        digest_md(bad)


def test_not_alerts_document(tmp_path: Path) -> None:
    with pytest.raises(ZapAlertsError, match="not a ZAP alerts document"):
        digest_md(_write_json(tmp_path, {"hello": "world"}))


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
    r = _run_cli(str(tmp_path / "nope.json"))
    assert r.returncode == 1
    assert "file not found" in r.stderr


def test_cli_invalid_json_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    r = _run_cli(str(bad))
    assert r.returncode == 2
    assert "invalid JSON" in r.stderr
