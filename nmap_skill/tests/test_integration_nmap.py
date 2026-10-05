"""Integration test (S1C.5): nmap skill scripts against a disposable nginx container.

Requires docker + nmap on the host; skipped otherwise. Run via `make integration`.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
VULN_SCAN = SKILL_DIR / "scripts" / "nmap_vuln_scan.sh"
RECON = SKILL_DIR / "scripts" / "nmap_recon.sh"


def _docker_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed"),
    pytest.mark.skipif(not _docker_usable(), reason="docker daemon not usable"),
]


def _ensure_image() -> None:
    r = subprocess.run(
        ["docker", "image", "inspect", "nginx:alpine"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if r.returncode == 0:
        return
    pull = subprocess.run(
        ["docker", "pull", "-q", "nginx:alpine"],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if pull.returncode != 0:
        pytest.skip(f"cannot pull nginx:alpine ({pull.stderr.strip()})")


@pytest.fixture()
def nginx_ip() -> Iterator[str]:
    _ensure_image()
    name = f"nmapskill-test-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "nginx:alpine"],
        capture_output=True,
        check=True,
        timeout=120,
    )
    try:
        ip = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                name,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()
        assert ip, "container has no IP address"
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with socket.create_connection((ip, 80), timeout=2):
                    break
            except OSError:
                time.sleep(0.5)
        else:
            msg = "nginx did not become reachable"
            pytest.fail(msg)
        yield ip
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            timeout=60,
            check=False,
        )


def test_vuln_scan_against_nginx(nginx_ip: str, tmp_path: Path) -> None:
    prefix = tmp_path / "vuln_scan"
    r = subprocess.run(
        [
            "bash",
            str(VULN_SCAN),
            nginx_ip,
            "80",
            str(prefix),
            "--host-timeout",
            "90s",
            "-T4",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"XML: {prefix}.xml" in r.stdout
    assert (tmp_path / "vuln_scan.xml").is_file()
    md_path = tmp_path / "vuln_scan.md"
    assert md_path.is_file()
    md = md_path.read_text(encoding="utf-8")
    assert "| 80 | tcp | open |" in md
    assert "nginx" in md.lower()


def test_recon_against_nginx(nginx_ip: str, tmp_path: Path) -> None:
    prefix = tmp_path / "recon"
    r = subprocess.run(
        [
            "bash",
            str(RECON),
            nginx_ip,
            str(prefix),
            "--host-timeout",
            "90s",
            "-T4",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"XML: {prefix}.xml" in r.stdout
    md_path = tmp_path / "recon.md"
    assert md_path.is_file()
    md = md_path.read_text(encoding="utf-8")
    assert "| 80 | tcp | open |" in md
    assert "nginx" in md.lower()
