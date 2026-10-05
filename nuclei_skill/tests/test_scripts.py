"""Static + CLI-validation tests for nuclei_skill scripts (fast, no nuclei needed).

The wrappers are tested with a stub ``nuclei`` binary injected via PATH so the
tests are deterministic on machines without nuclei installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_DIR / "scripts"
SCAN = SCRIPTS_DIR / "nuclei_scan.sh"
CUSTOM = SCRIPTS_DIR / "nuclei_custom.sh"
FIXTURE = SKILL_DIR / "examples" / "example_results.jsonl"


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
        timeout=60,
        check=False,
        env=env,
    )


def _env_with_stub_nuclei(tmp_path: Path, script_body: str) -> dict[str, str]:
    """PATH with a stub `nuclei` whose body writes its -jle output + a finding."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "nuclei"
    stub.write_text(script_body, encoding="utf-8")
    stub.chmod(0o755)
    return {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}


def _env_without_nuclei(tmp_path: Path) -> dict[str, str]:
    """PATH with only a few symlinked core tools (bash, cat, dirname) — no nuclei."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for tool in ("bash", "cat", "dirname"):
        target = shutil.which(tool)
        assert target is not None, f"{tool} not found"
        (bindir / tool).symlink_to(target)
    return {**os.environ, "PATH": str(bindir)}


STUB_ECHO = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -jle) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
cp "$NUCLEI_FIXTURE" "$out"
echo "stub nuclei ran"
"""


# --- static ----------------------------------------------------------------


def test_bash_syntax() -> None:
    for script in (SCAN, CUSTOM):
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
        [shellcheck, str(SCAN), str(CUSTOM)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_airgap_flags_are_hardcoded() -> None:
    """-duc (no template update) and -ni (no interactsh/OAST) are mandatory in
    the air-gapped lab — removing them would make scans hang on the network."""
    for script in (SCAN, CUSTOM):
        text = script.read_text(encoding="utf-8")
        assert "-duc" in text, f"{script.name}: -duc missing"
        assert "-ni" in text, f"{script.name}: -ni missing"


# --- nuclei_scan.sh CLI validation (no nuclei needed) ------------------------


def test_scan_requires_args() -> None:
    r = _run(SCAN)
    assert r.returncode == 2
    assert "Usage: nuclei_scan.sh" in r.stderr


def test_scan_rejects_flag_like_target() -> None:
    r = _run(SCAN, "-oops")
    assert r.returncode == 2


def test_scan_rejects_bad_severity() -> None:
    r = _run(SCAN, "10.0.0.1", "high;rm -rf /")
    assert r.returncode == 2
    assert "invalid severity" in r.stderr


def test_scan_missing_nuclei_exits_3(tmp_path: Path) -> None:
    env = _env_without_nuclei(tmp_path)
    r = _run(SCAN, "10.0.0.1", env=env)
    assert r.returncode == 3
    assert "nuclei not found" in r.stderr


def test_scan_missing_templates_dir_exits_4(tmp_path: Path) -> None:
    env = _env_with_stub_nuclei(tmp_path, STUB_ECHO)
    env["NUCLEI_TEMPLATES_DIR"] = str(tmp_path / "no-such-templates")
    r = _run(SCAN, "10.0.0.1", env=env)
    assert r.returncode == 4
    assert "templates not found" in r.stderr


# --- nuclei_scan.sh success path (stub) -------------------------------------


def test_scan_success_writes_findings_and_digest(tmp_path: Path) -> None:
    tpl = tmp_path / "tpl"
    tpl.mkdir()
    env = _env_with_stub_nuclei(tmp_path, STUB_ECHO)
    env["NUCLEI_TEMPLATES_DIR"] = str(tpl)
    env["NUCLEI_FIXTURE"] = str(FIXTURE)
    prefix = tmp_path / "scan_out"
    r = _run(SCAN, "http://10.0.0.1:8080", "high,critical", str(prefix), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "findings: 3" in r.stdout
    md = (tmp_path / "scan_out.md").read_text(encoding="utf-8")
    assert "## High (1)" in md
    assert "## Medium (1)" in md


def test_scan_no_findings(tmp_path: Path) -> None:
    tpl = tmp_path / "tpl"
    tpl.mkdir()
    env = _env_with_stub_nuclei(tmp_path, "#!/bin/sh\nexit 0\n")
    env["NUCLEI_TEMPLATES_DIR"] = str(tpl)
    r = _run(SCAN, "10.0.0.1", env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no findings" in r.stderr


# --- nuclei_custom.sh CLI validation ----------------------------------------


def test_custom_requires_args() -> None:
    r = _run(CUSTOM)
    assert r.returncode == 2
    assert "Usage: nuclei_custom.sh" in r.stderr


def test_custom_rejects_flag_like_template() -> None:
    r = _run(CUSTOM, "-oops", "10.0.0.1")
    assert r.returncode == 2


def test_custom_rejects_traversal_template() -> None:
    r = _run(CUSTOM, "/tmp/../etc/passwd", "10.0.0.1")
    assert r.returncode == 2
    assert ".." in r.stderr


def test_custom_missing_template_file(tmp_path: Path) -> None:
    r = _run(CUSTOM, str(tmp_path / "nope.yaml"), "10.0.0.1")
    assert r.returncode == 4
    assert "not found" in r.stderr


def test_custom_rejects_flag_like_target(tmp_path: Path) -> None:
    tpl = tmp_path / "t.yaml"
    tpl.write_text("id: x\n", encoding="utf-8")
    r = _run(CUSTOM, str(tpl), "-oops")
    assert r.returncode == 2


def test_custom_missing_nuclei_exits_3(tmp_path: Path) -> None:
    tpl = tmp_path / "t.yaml"
    tpl.write_text("id: x\n", encoding="utf-8")
    env = _env_without_nuclei(tmp_path)
    r = _run(CUSTOM, str(tpl), "10.0.0.1", env=env)
    assert r.returncode == 3


def test_custom_validation_failure_exits_4(tmp_path: Path) -> None:
    tpl = tmp_path / "t.yaml"
    tpl.write_text("id: x\n", encoding="utf-8")
    env = _env_with_stub_nuclei(tmp_path, "#!/bin/sh\nexit 1\n")
    r = _run(CUSTOM, str(tpl), "10.0.0.1", env=env)
    assert r.returncode == 4
    assert "validation failed" in r.stderr
