"""Integration tests (S1G.5): zap skill scripts against a disposable target.

Requires zaproxy on the host (apt install zaproxy); skipped otherwise. Run via
`make integration`. The tests start a tiny python http server in docker and
scan it with ZAP's quick scan + a custom automation plan.
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
QUICK = SKILL_DIR / "scripts" / "zap_quick_scan.sh"
PLAN = SKILL_DIR / "scripts" / "zap_plan_scan.sh"

PLAN_YAML = """env:
  contexts:
    - name: target
      urls:
        - "http://{ip}:8000/"
  parameters:
    failOnError: true
    progressToStdout: true
jobs:
  - type: requestor
    requests:
      - name: index-probe
        url: "http://{ip}:8000/"
        method: GET
        responseCode: 200
  - type: spider
    parameters:
      context: target
      maxDuration: 2
  - type: passiveScan-wait
    parameters:
      maxDuration: 2
  - type: report
    parameters:
      template: traditional-json
      reportDir: "."
      reportFile: report.json
"""

SERVER_SCRIPT = """from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "python-test")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>hello</h1><a href='/next'>next</a></body></html>")
    def log_message(self, *a):
        pass
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
"""


def _docker_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("zaproxy") is None, reason="zaproxy not installed"),
    pytest.mark.skipif(not _docker_usable(), reason="docker daemon not usable"),
]


def _ensure_image() -> None:
    r = subprocess.run(
        ["docker", "image", "inspect", "python:3.12-alpine"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if r.returncode == 0:
        return
    pull = subprocess.run(
        ["docker", "pull", "-q", "python:3.12-alpine"],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if pull.returncode != 0:
        pytest.skip(f"cannot pull python:3.12-alpine ({pull.stderr.strip()})")


@pytest.fixture()
def target_ip() -> Iterator[str]:
    _ensure_image()
    name = f"zapskill-test-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "python:3.12-alpine",
            "sh",
            "-c",
            SERVER_SCRIPT,
        ],
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
                with socket.create_connection((ip, 8000), timeout=2):
                    break
            except OSError:
                time.sleep(0.5)
        else:
            msg = "target did not become reachable"
            pytest.fail(msg)
        yield ip
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            timeout=60,
            check=False,
        )


def test_quick_scan_finds_index(target_ip: str, tmp_path: Path) -> None:
    prefix = tmp_path / "quick"
    r = subprocess.run(
        ["bash", str(QUICK), f"http://{target_ip}:8000", str(prefix)],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"Report: {prefix}.json" in r.stdout
    md = (tmp_path / "quick.md").read_text(encoding="utf-8")
    assert "# ZAP alerts digest" in md


def test_plan_scan_validates_and_runs(target_ip: str, tmp_path: Path) -> None:
    plan = tmp_path / "plan.yaml"
    plan.write_text(PLAN_YAML.format(ip=target_ip), encoding="utf-8")
    r = subprocess.run(
        ["bash", str(PLAN), str(plan)],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "plan finished" in r.stdout
    report = tmp_path / "report.json"
    assert report.is_file()
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "# ZAP alerts digest" in md


def test_plan_validation_failure(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("jobs: [unclosed\n", encoding="utf-8")
    r = subprocess.run(
        ["bash", str(PLAN), str(bad)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert r.returncode == 4
    assert "validation failed" in r.stderr
