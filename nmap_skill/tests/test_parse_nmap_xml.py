"""Unit tests for scripts/parse_nmap_xml.py, using examples/example_scan.xml."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import parse_nmap_xml
import pytest
from parse_nmap_xml import NmapXmlError, digest_md

SKILL_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = SKILL_DIR / "examples" / "example_scan.xml"
SCRIPT = SKILL_DIR / "scripts" / "parse_nmap_xml.py"


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _write_nmaprun(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scan.xml"
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" start="1785902400"'
        ' startstr="Tue Sep  8 12:00:00 2026" version="7.94SVN"'
        f' xmloutputversion="1.05">\n{body}\n</nmaprun>\n',
        encoding="utf-8",
    )
    return path


# --- committed fixture -------------------------------------------------------


def test_example_hosts() -> None:
    md = digest_md(EXAMPLE)
    assert "## Host 192.162.34.1 (fw.lab.local)" in md
    assert "## Host 192.161.7.1" in md


def test_example_metadata() -> None:
    md = digest_md(EXAMPLE)
    assert 'nmap -sV --script "vuln and not dos"' in md  # &quot; decoded
    assert "**Nmap version**: 7.94SVN" in md
    assert "**Elapsed**: 90.00s" in md
    assert "**Hosts**: 2 up, 0 down" in md
    assert "**Started**: Tue Sep  8 12:00:00 2026" in md


def test_example_port_rows() -> None:
    md = digest_md(EXAMPLE)
    assert "| 80 | tcp | open | http nginx 1.25.3 (default page) |" in md
    assert "| 8080 | tcp | open | http Go 1.26 http server (h2c enabled) |" in md
    assert "| 443 | tcp | open | ssl/https Go 1.26 http server |" in md
    assert "**Open ports: 1**" in md
    assert "**Open ports: 2**" in md


def test_example_extraports() -> None:
    md = digest_md(EXAMPLE)
    assert "_filtered (1 ports)_" in md
    assert "_closed (1 ports)_" in md


def test_example_status_and_mac() -> None:
    md = digest_md(EXAMPLE)
    assert "Status: **up** (reset)" in md
    assert "MAC: 02:42:AC:1A:00:01 (Docker)" in md


def test_example_script_outputs_verbatim() -> None:
    md = digest_md(EXAMPLE)
    assert "#### http-slowloris-check" in md
    assert "Vulnerable: the host is susceptible to slowloris" in md
    assert "#### http-headers" in md
    # multi-line output preserved inside a code fence
    assert "```\nHTTP/1.1 200 OK\nServer: nginx/1.25.3" in md


def test_example_host_script() -> None:
    md = digest_md(EXAMPLE)
    assert "### Host script results" in md
    assert "#### resolve" in md


# --- synthetic documents -----------------------------------------------------


def test_no_hosts(tmp_path: Path) -> None:
    md = digest_md(_write_nmaprun(tmp_path, ""))
    assert "No hosts reported." in md


def test_os_guesses_and_ipv6(tmp_path: Path) -> None:
    body = (
        '<host><status state="up" reason="reset"/>'
        '<address addr="2001:db8::1" addrtype="ipv6"/>'
        '<hostnames><hostname name="web1.lab.local" type="PTR"/></hostnames>'
        "<os>"
        '<osmatch name="Linux 5.15" accuracy="98"/>'
        '<osmatch name="Linux 4.15" accuracy="90"/>'
        "</os></host>"
    )
    md = digest_md(_write_nmaprun(tmp_path, body))
    assert "## Host 2001:db8::1 (web1.lab.local)" in md
    assert "OS guess: Linux 5.15 (98%)" in md
    assert "OS guess: Linux 4.15 (90%)" in md


def test_backtick_fence_grows(tmp_path: Path) -> None:
    body = (
        '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<script id="odd" output="has ``` inside"/></port></ports></host>'
    )
    md = digest_md(_write_nmaprun(tmp_path, body))
    assert "````\nhas ``` inside\n````" in md


def test_script_without_output(tmp_path: Path) -> None:
    body = (
        '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<script id="silent"/></port></ports></host>'
    )
    md = digest_md(_write_nmaprun(tmp_path, body))
    assert "#### silent" in md
    assert "_no output_" in md


def test_service_name_only_and_empty_service(tmp_path: Path) -> None:
    body = (
        '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
        "<ports>"
        '<port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh"/></port>'
        '<port protocol="udp" portid="1234"><state state="open"/></port>'
        "</ports></host>"
    )
    md = digest_md(_write_nmaprun(tmp_path, body))
    assert "| 22 | tcp | open | ssh |" in md
    assert "| 1234 | udp | open |  |" in md


def test_pre_and_post_scripts(tmp_path: Path) -> None:
    body = (
        '<prescript><script id="pre-probe" output="found 2 hosts"/></prescript>'
        '<postscript><script id="post-probe" output="done"/></postscript>'
    )
    md = digest_md(_write_nmaprun(tmp_path, body))
    assert "## Pre-scan scripts" in md
    assert "### pre-probe" in md
    assert "## Post-scan scripts" in md
    assert "### post-probe" in md


def test_fence_for_backtick_runs() -> None:
    assert parse_nmap_xml._fence_for("plain") == "```"
    assert parse_nmap_xml._fence_for("a`b") == "```"
    assert parse_nmap_xml._fence_for("```\nx\n```") == "````"


# --- error paths -------------------------------------------------------------


def test_nmapxmlerror_on_garbage(tmp_path: Path) -> None:
    bad = tmp_path / "bad.xml"
    bad.write_text("<unclosed>", encoding="utf-8")
    with pytest.raises(NmapXmlError, match="invalid XML"):
        digest_md(bad)


def test_nmapxmlerror_on_non_nmap_root(tmp_path: Path) -> None:
    other = tmp_path / "other.xml"
    other.write_text("<hello><world/></hello>", encoding="utf-8")
    with pytest.raises(NmapXmlError, match="not an nmap XML file"):
        digest_md(other)


# --- CLI ----------------------------------------------------------------------


def test_cli_stdout() -> None:
    r = _run_cli(str(EXAMPLE))
    assert r.returncode == 0, r.stderr
    assert "## Host 192.162.34.1 (fw.lab.local)" in r.stdout


def test_cli_writes_file(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "digest.md"
    r = _run_cli(str(EXAMPLE), "-o", str(out))
    assert r.returncode == 0, r.stderr
    assert "wrote" in r.stdout
    assert "## Host 192.161.7.1" in out.read_text(encoding="utf-8")


def test_cli_missing_file(tmp_path: Path) -> None:
    r = _run_cli(str(tmp_path / "nope.xml"))
    assert r.returncode == 1
    assert "file not found" in r.stderr


def test_cli_invalid_xml_exit_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.xml"
    bad.write_text("<unclosed>", encoding="utf-8")
    r = _run_cli(str(bad))
    assert r.returncode == 2
    assert "invalid XML" in r.stderr


def test_cli_not_nmap_root_exit_2(tmp_path: Path) -> None:
    other = tmp_path / "other.xml"
    other.write_text("<hello/>", encoding="utf-8")
    r = _run_cli(str(other))
    assert r.returncode == 2
    assert "not an nmap XML file" in r.stderr
