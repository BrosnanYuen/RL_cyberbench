"""Static + CLI-validation tests for wireshark_skill scripts (fast, no docker)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_DIR / "scripts"
CAPTURE = SCRIPTS_DIR / "capture.sh"
TRIAGE = SCRIPTS_DIR / "quick_triage.sh"


def _find_shellcheck() -> str | None:
    exe = shutil.which("shellcheck")
    if exe:
        return exe
    venv_bin = Path(__file__).resolve().parents[2] / ".venv" / "bin" / "shellcheck"
    if venv_bin.is_file():
        return str(venv_bin)
    return None


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_bash_syntax() -> None:
    for script in (CAPTURE, TRIAGE):
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
        [shellcheck, str(CAPTURE), str(TRIAGE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_capture_requires_args() -> None:
    r = _run(CAPTURE)
    assert r.returncode == 2
    assert "Usage: capture.sh" in r.stderr


def test_capture_rejects_bad_extension() -> None:
    r = _run(CAPTURE, "lo", "/tmp/out.txt", "5")
    assert r.returncode == 2
    assert ".pcap" in r.stderr


def test_capture_rejects_traversal() -> None:
    r = _run(CAPTURE, "lo", "/tmp/../etc/passwd.pcap", "5")
    assert r.returncode == 2


def test_capture_rejects_flag_like_args() -> None:
    assert _run(CAPTURE, "-i", "x.pcap").returncode == 2
    assert _run(CAPTURE, "lo", "x.pcap", "abc").returncode == 2
    assert _run(CAPTURE, "lo", "x.pcap", "5", "-oops").returncode == 2


def test_triage_requires_args() -> None:
    r = _run(TRIAGE)
    assert r.returncode == 2
    assert "Usage: quick_triage.sh" in r.stderr


def test_triage_rejects_bad_extension() -> None:
    r = _run(TRIAGE, "/etc/hosts")
    assert r.returncode == 2


def test_triage_rejects_traversal() -> None:
    r = _run(TRIAGE, "/tmp/../etc/shadow.pcap")
    assert r.returncode == 2


def test_triage_missing_file() -> None:
    r = _run(TRIAGE, "/tmp/definitely-missing-capture.pcap")
    assert r.returncode == 4
    assert "not found or empty" in r.stderr
