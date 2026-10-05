"""Static + CLI-validation tests for scapy_skill scripts (fast, no scapy needed)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_DIR / "scripts"
SCRIPTS = sorted(SCRIPTS_DIR.glob("*.py"))


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_scripts_compile() -> None:
    for script in SCRIPTS:
        compile(script.read_text(encoding="utf-8"), str(script), "exec")


def test_scripts_have_entrypoint_and_validation() -> None:
    for script in SCRIPTS:
        text = script.read_text(encoding="utf-8")
        assert 'if __name__ == "__main__"' in text
        assert "_validate(" in text, f"{script.name}: arguments not validated"


def test_arp_scan_requires_args() -> None:
    r = _run(str(SCRIPTS_DIR / "arp_scan.py"))
    assert r.returncode == 2
    assert "usage" in (r.stderr + r.stdout).lower()


def test_arp_scan_rejects_bad_cidr() -> None:
    r = _run(str(SCRIPTS_DIR / "arp_scan.py"), "not-a-cidr")
    assert r.returncode == 2
    assert "invalid CIDR" in r.stderr


def test_arp_scan_rejects_flag_like_iface() -> None:
    r = _run(str(SCRIPTS_DIR / "arp_scan.py"), "10.0.0.0/24", "--iface", "-oops")
    assert r.returncode == 2


def test_arp_scan_rejects_bad_timeout() -> None:
    r = _run(str(SCRIPTS_DIR / "arp_scan.py"), "10.0.0.0/24", "--timeout", "abc")
    assert r.returncode == 2


def test_arp_scan_rejects_negative_retries() -> None:
    r = _run(str(SCRIPTS_DIR / "arp_scan.py"), "10.0.0.0/24", "--retries", "-1")
    assert r.returncode == 2


def test_arp_spoof_requires_args() -> None:
    r = _run(str(SCRIPTS_DIR / "arp_spoof.py"))
    assert r.returncode == 2


def test_arp_spoof_rejects_bad_ip() -> None:
    r = _run(str(SCRIPTS_DIR / "arp_spoof.py"), "999.1.1.1", "10.0.0.1")
    assert r.returncode == 2
    assert "invalid target IP" in r.stderr


def test_arp_spoof_rejects_flag_like_iface() -> None:
    r = _run(
        str(SCRIPTS_DIR / "arp_spoof.py"), "10.0.0.1", "10.0.0.2", "--iface", "-oops"
    )
    assert r.returncode == 2


def test_arp_spoof_rejects_bad_interval() -> None:
    r = _run(
        str(SCRIPTS_DIR / "arp_spoof.py"), "10.0.0.1", "10.0.0.2", "--interval", "0"
    )
    assert r.returncode == 2


def test_ping_sweep_requires_args() -> None:
    r = _run(str(SCRIPTS_DIR / "ping_sweep.py"))
    assert r.returncode == 2


def test_ping_sweep_rejects_bad_cidr() -> None:
    r = _run(str(SCRIPTS_DIR / "ping_sweep.py"), "10.0.0.0../24")
    assert r.returncode == 2


def test_sniff_requires_args() -> None:
    r = _run(str(SCRIPTS_DIR / "sniff.py"))
    assert r.returncode == 2


def test_sniff_rejects_bad_extension() -> None:
    r = _run(str(SCRIPTS_DIR / "sniff.py"), "lo", "/tmp/out.txt")
    assert r.returncode == 2
    assert ".pcap" in r.stderr


def test_sniff_rejects_traversal() -> None:
    r = _run(str(SCRIPTS_DIR / "sniff.py"), "lo", "/tmp/../etc/passwd.pcap")
    assert r.returncode == 2


def test_sniff_rejects_flag_like_filter() -> None:
    r = _run(str(SCRIPTS_DIR / "sniff.py"), "lo", "/tmp/x.pcap", "--filter", "-oops")
    assert r.returncode == 2


def test_sniff_rejects_zero_count() -> None:
    r = _run(str(SCRIPTS_DIR / "sniff.py"), "lo", "/tmp/x.pcap", "--count", "0")
    assert r.returncode == 2
