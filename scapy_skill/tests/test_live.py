"""Integration tests for scapy_skill (marked; need scapy + live networking)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
PING_SWEEP = SCRIPTS_DIR / "ping_sweep.py"


def _scapy_available() -> bool:
    return (
        subprocess.run(
            [sys.executable, "-c", "import scapy"],
            capture_output=True,
            timeout=60,
            check=False,
        ).returncode
        == 0
    )


@pytest.mark.integration
@pytest.mark.skipif(not _scapy_available(), reason="scapy not installed")
def test_ping_sweep_loopback() -> None:
    r = subprocess.run(
        [sys.executable, str(PING_SWEEP), "127.0.0.1/32", "--timeout", "2"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    assert "127.0.0.1" in r.stdout
    assert "1 live host(s)" in r.stdout


@pytest.mark.integration
@pytest.mark.skipif(not _scapy_available(), reason="scapy not installed")
def test_arp_scan_empty_subnet_exits_1() -> None:
    r = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "arp_scan.py"),
            "192.0.2.0/30",
            "--timeout",
            "1",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert r.returncode == 1
    assert "No ARP responses" in r.stdout
