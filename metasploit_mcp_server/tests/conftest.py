"""Shared pytest fixtures for metasploit_mcp_server tests.

``recorded_rpc`` loads ``fixtures/recorded_rpc.json`` — real msfrpcd
response hashes recorded from a live Metasploit 6.5.0-dev daemon
(``msgpack`` decoded, strings normalized, volatile token replaced) and
replayed byte-for-byte by the mock transport in ``test_rpc_mock.py``.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
RECORDED = FIXTURES / "recorded_rpc.json"

HAS_MSF = shutil.which("msfrpcd") is not None


#: real-daemon tests only run when the operator opts in (and are marked
#: ``msf_live`` so ``pytest -m msf_live`` can select them)
def msf_live(obj):
    """Decorator: mark a test msf_live and skip it unless MSF_LIVE=1."""
    obj = pytest.mark.skipif(
        os.environ.get("MSF_LIVE") != "1",
        reason="set MSF_LIVE=1 for live msfrpcd tests",
    )(obj)
    return pytest.mark.msf_live(obj)


@pytest.fixture(scope="session")
def recorded_rpc() -> dict:
    """Return the recorded RPC hashes: label -> [http_status, decoded_value]."""
    if not RECORDED.exists():
        pytest.skip(f"fixture {RECORDED} missing")
    return json.loads(RECORDED.read_text(encoding="utf-8"))
