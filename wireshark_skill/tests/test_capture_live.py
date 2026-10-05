"""Integration test (S1D.4): live capture on a docker bridge network.

Runs capture.sh inside a container (root, NET_RAW available there), generates
traffic, then verifies with capinfos (>=1 packet) and quick_triage.sh.
Requires docker + tshark/capinfos on the host; skipped otherwise.
Run via `make integration`.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_DIR / "scripts"
CAPTURE = SCRIPTS_DIR / "capture.sh"
TRIAGE = SCRIPTS_DIR / "quick_triage.sh"


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
    pytest.mark.skipif(
        shutil.which("tshark") is None or shutil.which("capinfos") is None,
        reason="tshark/capinfos not installed",
    ),
    pytest.mark.skipif(not _docker_usable(), reason="docker daemon not usable"),
]


def _ensure_image() -> None:
    r = subprocess.run(
        ["docker", "image", "inspect", "alpine:3.20"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if r.returncode == 0:
        return
    pull = subprocess.run(
        ["docker", "pull", "-q", "alpine:3.20"],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if pull.returncode != 0:
        pytest.skip(f"cannot pull alpine:3.20 ({pull.stderr.strip()})")


def _dexec(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=check,
    )


@pytest.fixture()
def bridge_lab(tmp_path: Path):
    """Capture container on a fresh docker bridge network; yields (container, network, tmp)."""
    _ensure_image()
    name = f"wscapture-test-{uuid.uuid4().hex[:8]}"
    network = f"{name}-net"
    subprocess.run(
        ["docker", "network", "create", network],
        capture_output=True,
        check=True,
        timeout=60,
    )
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--network",
            network,
            "-v",
            f"{SCRIPTS_DIR}:/skills:ro",
            "-v",
            f"{tmp_path}:/out",
            "alpine:3.20",
            "sleep",
            "300",
        ],
        capture_output=True,
        check=True,
        timeout=120,
    )
    try:
        # shell + capture tools inside the container (tshark optional: gives
        # capture.sh the capinfos branch; tcpdump path works without it)
        r = _dexec(name, "apk", "add", "--no-cache", "bash", "tcpdump", check=False)
        if r.returncode != 0:
            pytest.skip(f"cannot apk add in container ({r.stderr.strip()})")
        _dexec(name, "apk", "add", "--no-cache", "tshark", check=False)
        yield name, network, tmp_path
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            timeout=60,
            check=False,
        )
        subprocess.run(
            ["docker", "network", "rm", network],
            capture_output=True,
            timeout=60,
            check=False,
        )


def test_capture_five_seconds_on_docker_bridge(bridge_lab) -> None:
    container, network, tmp = bridge_lab

    gateway = subprocess.run(
        [
            "docker",
            "network",
            "inspect",
            "-f",
            "{{(index .IPAM.Config 0).Gateway}}",
            network,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout.strip()

    pcap_out = tmp / "live.pcap"
    r = subprocess.run(
        [
            "docker",
            "exec",
            "-d",
            container,
            "bash",
            "/skills/capture.sh",
            "eth0",
            "/out/live.pcap",
            "6",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert r.returncode == 0

    # traffic generator: ping the network gateway for the capture window
    _dexec(container, "ping", "-c", "8", "-i", "1", gateway, check=False)

    deadline = time.time() + 15
    while time.time() < deadline and not pcap_out.exists():
        time.sleep(1)
    assert pcap_out.exists(), "live.pcap was not written"

    # capture.sh runs for 6 s; give it time to finish and flush
    time.sleep(6)

    count = subprocess.run(
        ["capinfos", "-c", str(pcap_out)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    packets = int(
        next(
            line.split()[-1]
            for line in count.splitlines()
            if "Number of packets" in line
        )
    )
    assert packets >= 1, "capture holds zero packets"

    triage = subprocess.run(
        ["bash", str(TRIAGE), str(pcap_out)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert triage.returncode == 0, triage.stderr
    assert f"## Triage: {pcap_out}" in triage.stdout
    assert "### Protocol hierarchy" in triage.stdout
    assert "### IP conversations" in triage.stdout
