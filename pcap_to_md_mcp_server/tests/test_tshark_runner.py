"""Security and robustness tests for pcap_to_md.tshark_runner (PLAN S1A.1)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pcap_to_md.tshark_runner import (
    TsharkError,
    TsharkTimeoutError,
    TsharkValidationError,
    run_tshark,
    truncate_output,
    validate_pcap_path,
)

from .conftest import requires_tshark


def test_truncate_output_short_text_passes_through():
    text = "hello"
    assert truncate_output(text, 8000) == text


def test_truncate_output_head_tail_and_marker():
    text = "x" * 1000
    out = truncate_output(text, 100)
    assert len(out) <= 100 + 5  # marker is bounded
    assert "[... " in out and "chars truncated ...]" in out
    assert out.startswith("x") and out.rstrip().endswith("x")


def test_truncate_output_degenerate_cap():
    out = truncate_output("x" * 100, 10)
    assert out == "[... 100 chars truncated ...]"


def test_validate_pcap_path_rejects_traversal(tmp_path: Path):  # noqa: ARG001
    with pytest.raises(TsharkValidationError, match="traversal"):
        validate_pcap_path("safe/../etc/passwd.pcap")


@pytest.mark.parametrize(
    "bad", ["file.txt", "file", "file.pcap;id", "", "file.pcapng.exe"]
)
def test_validate_pcap_path_rejects_bad_extensions(bad: str, tmp_path: Path):
    with pytest.raises(TsharkValidationError):
        validate_pcap_path(bad, root=tmp_path)


def test_validate_pcap_path_rejects_missing(tmp_path: Path):
    with pytest.raises(TsharkValidationError, match="not found"):
        validate_pcap_path(tmp_path / "nope.pcap")


def test_validate_pcap_path_rejects_directory(tmp_path: Path):
    d = tmp_path / "dir.pcap"
    d.mkdir()
    with pytest.raises(TsharkValidationError):
        validate_pcap_path(d)


def test_validate_pcap_path_accepts_allowed_extensions(tmp_path: Path):
    for ext in (".pcap", ".pcapng", ".cap"):
        f = tmp_path / f"ok{ext}"
        f.write_bytes(b"\x00")
        assert validate_pcap_path(f).suffix == ext


def test_validate_pcap_path_rejects_fifos(tmp_path: Path):
    import os

    fifo = tmp_path / "pipe.pcap"
    os.mkfifo(fifo)
    with pytest.raises(TsharkValidationError):
        validate_pcap_path(fifo)


def test_validate_pcap_path_rejects_null_byte():
    with pytest.raises(TsharkValidationError, match="null byte"):
        validate_pcap_path("evil\x00.pcap")


def test_validate_pcap_path_relative_resolves_against_root(tmp_path: Path):
    f = tmp_path / "ok.pcap"
    f.write_bytes(b"\x00")
    assert validate_pcap_path("ok.pcap", root=tmp_path) == f.resolve()


def test_validate_pcap_path_absolute_outside_root_rejected(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "elsewhere.pcap"
    outside.write_bytes(b"\x00")
    with pytest.raises(TsharkValidationError, match="outside the allowed root"):
        validate_pcap_path(outside, root=root)


def test_validate_pcap_path_symlink_escape_outside_root_rejected(tmp_path: Path):
    """A symlink inside root pointing at a file outside root must be rejected."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.pcap"
    outside.write_bytes(b"\x00")
    (root / "link.pcap").symlink_to(outside)
    with pytest.raises(TsharkValidationError, match="outside the allowed root"):
        validate_pcap_path(root / "link.pcap", root=root)


def test_validate_pcap_path_symlink_inside_root_accepted(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "real.pcap"
    target.write_bytes(b"\x00")
    (root / "link.pcap").symlink_to(target)
    assert validate_pcap_path(root / "link.pcap", root=root) == target.resolve()


def test_truncate_output_zero_or_negative_cap_means_unlimited():
    assert truncate_output("x" * 50, 0) == "x" * 50
    assert truncate_output("x" * 50, -5) == "x" * 50


def test_has_truncation_marker_detects_only_real_markers():
    from pcap_to_md.tshark_runner import has_truncation_marker

    assert has_truncation_marker(truncate_output("x" * 1000, 100)) is True
    assert has_truncation_marker(truncate_output("x" * 100, 10)) is True
    # exact-fit and short outputs carry no marker
    assert has_truncation_marker("x" * 100) is False
    assert has_truncation_marker(truncate_output("x" * 100, 1000)) is False
    # truncated text can be *shorter* than the cap and still detected
    short = truncate_output("x" * 500, 120)
    assert len(short) < 120
    assert has_truncation_marker(short) is True


def test_run_tshark_rejects_output_above_hard_cap():
    from pcap_to_md.tshark_runner import HARD_OUTPUT_CAP, TsharkValidationError

    with pytest.raises(TsharkValidationError, match="exceeds hard cap"):
        asyncio.run(run_tshark(["-r", "x.pcap"], max_output=HARD_OUTPUT_CAP + 1))


def test_capinfos_is_a_run_tshark_wrapper_without_shell():
    """Sanity: run_capinfos shares the hardened subprocess path (no shell)."""
    from pcap_to_md.tshark_runner import run_capinfos

    with pytest.raises(TsharkError, match="capinfos"):
        asyncio.run(run_capinfos(["-c", "nope.pcap"]))


@requires_tshark
def test_injection_attempts_are_inert(http_pcap: Path):
    """Metacharacters in arguments must reach tshark as plain argv (no shell)."""
    from pcap_to_md.tshark_runner import run_tshark

    # 1. valid display filter containing shell metachars (|): passes them
    #    through to tshark's filter parser — never to a shell.
    out = asyncio.run(run_tshark(["-r", str(http_pcap), "-Y", "http || dns"]))
    assert "GET /index.html" in out  # only matching packets, no shell error

    # 2. invalid display filter with ';': tshark itself rejects it (exit != 0) —
    #    proving the string was not interpreted by a shell.
    from pcap_to_md.tshark_runner import TsharkError

    with pytest.raises(TsharkError):
        asyncio.run(run_tshark(["-r", str(http_pcap), "-Y", "http; rm -rf /"]))


@requires_tshark
def test_timeout_is_enforced(http_pcap: Path):
    with pytest.raises(TsharkTimeoutError):
        asyncio.run(run_tshark(["-r", str(http_pcap), "-c", "5"], timeout=0.05))


@requires_tshark
def test_huge_output_is_truncated(http_pcap: Path):
    out = asyncio.run(run_tshark(["-r", str(http_pcap), "-T", "json"], max_output=500))
    assert len(out) <= 500 + 60
    assert "chars truncated" in out


@requires_tshark
def test_missing_tshark_binary(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PATH", str(Path(__file__).parent))  # no tshark here
    with pytest.raises(TsharkError, match="not found"):
        asyncio.run(run_tshark(["--version"]))
