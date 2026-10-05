"""Static + CLI-validation tests for zap_skill scripts (fast, no ZAP needed).

The wrappers are tested with stub ``zap.sh`` binaries injected via PATH so the
tests are deterministic on machines without zaproxy installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_DIR / "scripts"
QUICK = SCRIPTS_DIR / "zap_quick_scan.sh"
PLAN = SCRIPTS_DIR / "zap_plan_scan.sh"
DAEMON = SCRIPTS_DIR / "zap_daemon.sh"
FIXTURE = SKILL_DIR / "examples" / "example_alerts.json"


def _find_shellcheck() -> str | None:
    exe = shutil.which("shellcheck")
    if exe:
        return exe
    venv_bin = Path(__file__).resolve().parents[2] / ".venv" / "bin" / "shellcheck"
    if venv_bin.is_file():
        return str(venv_bin)
    return None


def _run(
    script: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
    )


def _env_with_stub_zap(tmp_path: Path, script_body: str) -> dict[str, str]:
    """PATH with a stub `zaproxy` whose body copies a fixture to -quickout."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "zaproxy"
    stub.write_text(script_body, encoding="utf-8")
    stub.chmod(0o755)
    return {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}


def _env_without_zap(tmp_path: Path) -> dict[str, str]:
    """PATH with only a few symlinked core tools (bash, cat, dirname) — no zap.sh."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for tool in ("bash", "cat", "dirname", "basename", "printf", "date", "mkdir"):
        target = shutil.which(tool)
        assert target is not None, f"{tool} not found"
        (bindir / tool).symlink_to(target)
    return {**os.environ, "PATH": str(bindir)}


STUB_ECHO = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -quickout) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
cp "$ZAP_FIXTURE" "$out"
echo "stub zap ran"
"""


# --- static ----------------------------------------------------------------


def test_bash_syntax() -> None:
    for script in (QUICK, PLAN, DAEMON):
        r = subprocess.run(
            ["bash", "-n", str(script)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert r.returncode == 0, f"{script}: {r.stderr}"


@pytest.mark.skipif(_find_shellcheck() is None, reason="shellcheck not installed")
def test_shellcheck_clean() -> None:
    shellcheck = _find_shellcheck()
    assert shellcheck is not None
    r = subprocess.run(
        [shellcheck, str(QUICK), str(PLAN), str(DAEMON)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_airgap_flags_are_hardcoded() -> None:
    """-silent (no unsolicited requests/update checks) and -notel (no telemetry)
    are mandatory in the air-gapped lab — removing them would make ZAP phone home."""
    for script in (QUICK, PLAN, DAEMON):
        text = script.read_text(encoding="utf-8")
        assert "-silent" in text, f"{script.name}: -silent missing"
        assert "-notel" in text, f"{script.name}: -notel missing"


# --- zap_quick_scan.sh CLI validation --------------------------------------


def test_quick_requires_args() -> None:
    r = _run(QUICK)
    assert r.returncode == 2
    assert "Usage: zap_quick_scan.sh" in r.stderr


def test_quick_rejects_flag_like_target() -> None:
    r = _run(QUICK, "-oops")
    assert r.returncode == 2


def test_quick_missing_zap_exits_3(tmp_path: Path) -> None:
    r = _run(QUICK, "http://10.0.0.1:8080", env=_env_without_zap(tmp_path))
    assert r.returncode == 3
    assert "zaproxy not found" in r.stderr


def test_quick_success_writes_report_and_digest(tmp_path: Path) -> None:
    env = _env_with_stub_zap(tmp_path, STUB_ECHO)
    env["ZAP_FIXTURE"] = str(FIXTURE)
    prefix = tmp_path / "scan_out"
    r = _run(QUICK, "http://10.0.0.1:8080", str(prefix), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"Report: {prefix}.json" in r.stdout
    md = (tmp_path / "scan_out.md").read_text(encoding="utf-8")
    assert "## High (1)" in md
    assert "## Medium (1)" in md


def test_quick_missing_report_exits_4(tmp_path: Path) -> None:
    env = _env_with_stub_zap(tmp_path, "#!/bin/sh\nexit 0\n")
    r = _run(QUICK, "http://10.0.0.1:8080", str(tmp_path / "none"), env=env)
    assert r.returncode == 4
    assert "JSON report not found" in r.stderr


# --- zap_plan_scan.sh CLI validation ----------------------------------------


def test_plan_requires_args() -> None:
    r = _run(PLAN)
    assert r.returncode == 2
    assert "Usage: zap_plan_scan.sh" in r.stderr


def test_plan_rejects_flag_like_plan() -> None:
    r = _run(PLAN, "-oops")
    assert r.returncode == 2


def test_plan_rejects_traversal() -> None:
    r = _run(PLAN, "/tmp/../etc/passwd")
    assert r.returncode == 2
    assert ".." in r.stderr


def test_plan_missing_file_exits_4(tmp_path: Path) -> None:
    r = _run(PLAN, str(tmp_path / "nope.yaml"))
    assert r.returncode == 4
    assert "not found" in r.stderr


def test_plan_missing_zap_exits_3(tmp_path: Path) -> None:
    plan = tmp_path / "p.yaml"
    plan.write_text("env:\n  contexts: []\n", encoding="utf-8")
    r = _run(PLAN, str(plan), env=_env_without_zap(tmp_path))
    assert r.returncode == 3


def test_plan_validation_failure_exits_4(tmp_path: Path) -> None:
    plan = tmp_path / "p.yaml"
    plan.write_text("env:\n  contexts: []\n", encoding="utf-8")
    env = _env_with_stub_zap(tmp_path, "#!/bin/sh\nexit 1\n")
    r = _run(PLAN, str(plan), env=env)
    assert r.returncode == 4
    assert "validation failed" in r.stderr


def test_plan_success_digests_report(tmp_path: Path) -> None:
    plan = tmp_path / "p.yaml"
    plan.write_text("env:\n  contexts: []\n", encoding="utf-8")
    report = tmp_path / "report.json"
    report.write_bytes(FIXTURE.read_bytes())
    env = _env_with_stub_zap(tmp_path, "#!/bin/sh\nexit 0\n")
    env["ZAP_REPORT"] = str(report)
    r = _run(PLAN, str(plan), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "plan finished (zap exit code: 0)" in r.stdout
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "## High (1)" in md


# --- zap_daemon.sh CLI validation -------------------------------------------


def test_daemon_requires_action() -> None:
    r = _run(DAEMON)
    assert r.returncode == 2


def test_daemon_rejects_bad_action() -> None:
    r = _run(DAEMON, "restart")
    assert r.returncode == 2


def test_daemon_missing_zap_exits_3(tmp_path: Path) -> None:
    r = _run(DAEMON, "start", env=_env_without_zap(tmp_path))
    assert r.returncode == 3
