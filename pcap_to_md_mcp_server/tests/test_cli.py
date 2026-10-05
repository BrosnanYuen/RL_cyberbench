"""End-to-end CLI tests for ``pcap2md`` (previously untested code path)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_to_md.cli import main

from .conftest import requires_tshark


def _run(argv: list[str], capsys) -> tuple[int, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


@requires_tshark
def test_cli_summary_writes_file(http_pcap: Path, tmp_path: Path, capsys):
    out = tmp_path / "summary.md"
    code, _ = _run(["summary", str(http_pcap), "-o", str(out)], capsys)
    assert code == 0
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("# Packet summary — http.pcap")


@requires_tshark
def test_cli_summary_prints_to_stdout_without_out(http_pcap, capsys):
    code, text = _run(["summary", str(http_pcap)], capsys)
    assert code == 0
    assert "# Packet summary — http.pcap" in text


@requires_tshark
def test_cli_full_creates_packet_dir(http_pcap: Path, tmp_path: Path, capsys):
    out = tmp_path / "md"
    code, text = _run(["full", str(http_pcap), "-o", str(out), "-c", "3"], capsys)
    assert code == 0
    assert "wrote" in text
    assert len(list(out.glob("packet_*.md"))) == 3
    assert (out / "index.md").exists()


@requires_tshark
def test_cli_report_writes_file(http_pcap: Path, tmp_path: Path, capsys):
    out = tmp_path / "report.md"
    code, _ = _run(["report", str(http_pcap), "-o", str(out)], capsys)
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# Capture report — http.pcap")
    assert "## Protocol hierarchy" in text


@requires_tshark
def test_cli_follow_stream(http_pcap, capsys):
    code, text = _run(
        ["follow", str(http_pcap), "--proto", "tcp", "--stream", "0"], capsys
    )
    assert code == 0
    assert "GET /index.html HTTP/1.1" in text
    # header/length noise is parsed out, not dumped into the code blocks
    assert "49\n" not in text and "=====" not in text
    assert "**Node 0** — `192.168.1.100:49152`" in text


@requires_tshark
def test_cli_report_respects_packet_cap(http_pcap, capsys):
    """-c caps the frames the -z taps read (regression: report used to crash
    with an unexpected-keyword TypeError when --max-packets was given)."""
    code, text = _run(["report", str(http_pcap), "-c", "2"], capsys)
    assert code == 0
    assert "## Protocol hierarchy" in text
    assert "frames:2" in text  # tap really was capped
    assert "data-text-lines" not in text  # packet 2 was never read


def test_cli_report_rejects_display_filter_at_argparse_level(http_pcap):
    """-Y cannot filter -z taps, so report no longer advertises --filter."""
    with pytest.raises(SystemExit) as exc:
        main(["report", str(http_pcap), "--filter", "http"])
    assert exc.value.code == 2


def test_cli_follow_rejects_unsupported_options(http_pcap):
    """follow indexes streams over the whole capture: --filter/--max-packets
    are not advertised (they used to be silently ignored)."""
    with pytest.raises(SystemExit) as exc:
        main(["follow", str(http_pcap), "--filter", "http"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["follow", str(http_pcap), "-c", "3"])
    assert exc.value.code == 2


def test_cli_errors_on_missing_pcap(tmp_path, capsys):
    code, text = _run(["summary", str(tmp_path / "nope.pcap")], capsys)
    assert code == 1
    assert "error:" in text


def test_cli_errors_on_traversal_path(capsys):
    code, text = _run(["summary", "../etc/passwd.pcap"], capsys)
    assert code == 1
    assert "traversal" in text


def test_cli_rejects_negative_max_packets(http_pcap, capsys):
    code, text = _run(["summary", str(http_pcap), "-c", "-4"], capsys)
    assert code == 1
    assert "max_packets" in text


def test_cli_requires_a_subcommand():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2  # argparse usage error


def test_cli_rejects_unknown_proto_at_argparse_level(http_pcap):
    # --proto is an argparse choices list, so a bad value never reaches tshark
    with pytest.raises(SystemExit) as exc:
        main(["follow", str(http_pcap), "--proto", "smtp"])
    assert exc.value.code == 2


def test_cli_summary_validates_invalid_json_output(http_pcap, capsys, monkeypatch):
    """A corrupted tshark JSON payload becomes a clean CLI error (exit 1)."""
    from pcap_to_md import summary as summary_mod

    async def fake_run(*_a, **_k):
        return "{corrupt"

    monkeypatch.setattr(summary_mod, "run_tshark", fake_run)
    code, text = _run(["summary", str(http_pcap)], capsys)
    assert code == 1
    assert "could not parse" in text
