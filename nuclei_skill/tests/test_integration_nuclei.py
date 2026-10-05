"""Integration tests (S1F.5): nuclei skill scripts against a disposable nginx container.

Requires docker + nuclei on the host; skipped otherwise. Run via `make integration`.
The tests use a self-contained custom template (deterministic match on the nginx
welcome page) so they do NOT depend on the community template library.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
SCAN = SKILL_DIR / "scripts" / "nuclei_scan.sh"
CUSTOM = SKILL_DIR / "scripts" / "nuclei_custom.sh"

NGINX_TEMPLATE = """id: nginx-welcome-check
info:
  name: Nginx welcome page check
  severity: high
  description: Detects the default nginx welcome page (deterministic lab test)
  tags: lab,test
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "Welcome to nginx!"
"""

NEVER_MATCH_TEMPLATE = """id: never-match-check
info:
  name: Check that never matches
  severity: high
  description: Matches a string that nginx never serves
  tags: lab,test
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "definitely-not-served-by-nginx"
"""


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
    pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei not installed"),
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
    name = f"nucleiskill-test-{uuid.uuid4().hex[:8]}"
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


def test_custom_template_finds_nginx(nginx_ip: str, tmp_path: Path) -> None:
    tpl = tmp_path / "nginx_welcome.yaml"
    tpl.write_text(NGINX_TEMPLATE, encoding="utf-8")
    prefix = tmp_path / "custom"
    r = subprocess.run(
        ["bash", str(CUSTOM), str(tpl), nginx_ip, str(prefix)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "findings: 1" in r.stdout
    assert "Markdown digest:" in r.stdout
    md = (tmp_path / "custom.md").read_text(encoding="utf-8")
    assert "## High (1)" in md
    assert "Nginx welcome page check" in md


def test_custom_template_no_match(nginx_ip: str, tmp_path: Path) -> None:
    tpl = tmp_path / "never.yaml"
    tpl.write_text(NEVER_MATCH_TEMPLATE, encoding="utf-8")
    r = subprocess.run(
        ["bash", str(CUSTOM), str(tpl), nginx_ip, str(tmp_path / "none")],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no findings" in r.stderr


def test_custom_template_validation_failure(nginx_ip: str, tmp_path: Path) -> None:
    tpl = tmp_path / "broken.yaml"
    tpl.write_text("id: broken\ninfo: [unclosed\n", encoding="utf-8")
    r = subprocess.run(
        ["bash", str(CUSTOM), str(tpl), nginx_ip, str(tmp_path / "broken")],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert r.returncode == 4
    assert "validation failed" in r.stderr


def test_scan_wrapper_with_custom_template_dir(nginx_ip: str, tmp_path: Path) -> None:
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "nginx_welcome.yaml").write_text(NGINX_TEMPLATE, encoding="utf-8")
    env = {**os.environ, "NUCLEI_TEMPLATES_DIR": str(tpl_dir)}
    prefix = tmp_path / "scan"
    r = subprocess.run(
        ["bash", str(SCAN), nginx_ip, "high", str(prefix)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        env=env,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "findings: 1" in r.stdout
    md = (tmp_path / "scan.md").read_text(encoding="utf-8")
    assert "Nginx welcome page check" in md
