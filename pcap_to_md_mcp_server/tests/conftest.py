"""Shared pytest fixtures: pcap fixture generation via text2pcap + conftest utils."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
HEX = FIXTURES / "http.hex"
PCAP = FIXTURES / "http.pcap"

HAS_TSHARK = shutil.which("tshark") is not None
HAS_TEXT2PCAP = shutil.which("text2pcap") is not None

requires_tshark = pytest.mark.skipif(
    not HAS_TSHARK, reason="tshark not installed on this machine"
)


def ensure_pcap() -> Path:
    """Return the committed http.pcap, regenerating it from http.hex if needed."""
    if PCAP.exists():
        return PCAP
    if not (HAS_TEXT2PCAP and HEX.exists()):
        pytest.skip("fixture pcap missing and text2pcap unavailable")
    subprocess.run(
        ["text2pcap", "-q", str(HEX), str(PCAP)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return PCAP


@pytest.fixture()
def http_pcap(tmp_path: Path) -> Path:
    """Copy of the committed fixture pcap (tests never mutate the original)."""
    src = ensure_pcap()
    dst = tmp_path / "http.pcap"
    shutil.copy2(src, dst)
    return dst
