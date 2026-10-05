"""Safe subprocess wrapper around ``tshark`` (and ``capinfos``).

Security model (per PLAN.md S1A.1):
- Only ``asyncio.create_subprocess_exec`` is used — never ``shell=True``.
- Input paths are validated against an allowlist of extensions
  (``.pcap`` / ``.pcapng`` / ``.cap``), must exist, must be regular files,
  and may not contain ``..`` components or symlink tricks resolved outside
  the given root.
- Output is capped: anything above ``max_output`` characters is truncated to
  head + tail with an explicit ``[... N chars truncated ...]`` marker.
- Every command has a hard timeout (default 300 s).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

#: exact marker written by truncate_output() between head and tail
_TRUNCATION_MARKER_RE = re.compile(r"\[\.\.\. \d+ chars truncated \.\.\.\]")


@contextlib.contextmanager
def suppress_terminated_pipe():
    """Swallow 'Event loop is closed' noise from late transport cleanup."""
    with contextlib.suppress(RuntimeError):
        yield


__all__ = [
    "ALLOWED_EXTENSIONS",
    "TsharkError",
    "TsharkTimeoutError",
    "TsharkValidationError",
    "has_truncation_marker",
    "run_tshark",
    "truncate_output",
    "validate_pcap_path",
]

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

DEFAULT_TIMEOUT = 300.0
DEFAULT_MAX_OUTPUT = 8000

#: Largest allowed truncation window (chars). Kept high enough for -T json
#: full-tree output of a single packet while still bounding memory.
HARD_OUTPUT_CAP = 200_000_000


class TsharkError(Exception):
    """tshark (or capinfos) exited non-zero."""


class TsharkTimeoutError(TsharkError):
    """The subprocess exceeded its wall-clock budget."""


class TsharkValidationError(TsharkError):
    """A requested input path or argument failed security validation."""


def has_truncation_marker(text: str) -> bool:
    """Return True when *text* carries the head+tail truncation marker.

    Detect truncation by the marker rather than by comparing lengths: a
    truncated document is shorter than *max_output* (the marker has its own
    length) and a complete document can be exactly as long as the cap, so
    length comparisons misclassify both directions.
    """
    return _TRUNCATION_MARKER_RE.search(text) is not None


def truncate_output(text: str, max_output: int = DEFAULT_MAX_OUTPUT) -> str:
    """Return *text* truncated to *max_output* chars as head + tail + marker."""
    if max_output <= 0 or len(text) <= max_output:
        return text
    if max_output < 40:  # degenerate cap: keep nothing but the marker
        return f"[... {len(text)} chars truncated ...]"
    keep = max_output - 40  # room for the marker itself
    head = keep // 2
    tail = keep - head
    return (
        f"{text[:head]}\n[... {len(text) - keep} chars truncated ...]\n{text[-tail:]}"
    )


def validate_pcap_path(
    pcap_path: str | os.PathLike[str], root: str | os.PathLike[str] | None = None
) -> Path:
    """Validate and return *pcap_path* as an absolute :class:`Path`.

    Rejects: missing files, directories, special files, disallowed
    extensions, ``..`` components and (when *root* is given) paths that
    resolve outside *root* (including via symlinks).
    """
    raw = str(pcap_path)
    if "\x00" in raw:
        raise TsharkValidationError("path contains a null byte")
    if ".." in Path(raw).parts:
        raise TsharkValidationError("path traversal ('..') is not allowed")

    path = Path(raw)
    if not path.is_absolute():
        path = (Path(root) if root is not None else Path.cwd()) / path
    path = path.resolve()

    if root is not None:
        root_resolved = Path(root).resolve()
        if not path.is_relative_to(root_resolved):
            raise TsharkValidationError(
                f"path resolves outside the allowed root: {path}"
            )

    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise TsharkValidationError(
            f"extension {path.suffix!r} not allowed "
            f"(allowed: {sorted(ALLOWED_EXTENSIONS)})"
        )
    if not path.exists():
        raise TsharkValidationError(f"file not found: {path}")
    if not path.is_file():
        raise TsharkValidationError(f"not a regular file: {path}")
    try:
        st = path.stat()
        if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode):
            raise TsharkValidationError(f"not a regular file: {path}")
    except TsharkValidationError:
        raise
    except OSError as exc:  # pragma: no cover - platform dependent
        raise TsharkValidationError(f"cannot stat {path}: {exc}") from exc
    return path


@dataclass(frozen=True)
class TsharkResult:
    """Raw result of one subprocess run."""

    stdout: str
    stderr: str
    returncode: int


async def run_tshark(
    args: Sequence[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> str:
    """Run ``tshark`` with *args* (no shell) and return capped stdout.

    *args* must not include the ``tshark`` binary itself.
    """
    return await _run_capped("tshark", args, timeout, max_output)


async def run_capinfos(
    args: Sequence[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> str:
    """Run ``capinfos`` with *args* (no shell) and return capped stdout."""
    return await _run_capped("capinfos", args, timeout, max_output)


async def _run_capped(
    binary: str, args: Sequence[str], timeout: float, max_output: int
) -> str:
    if max_output > HARD_OUTPUT_CAP:
        raise TsharkValidationError(
            f"max_output {max_output} exceeds hard cap {HARD_OUTPUT_CAP}"
        )
    argv = [binary, *args]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise TsharkError(
            f"{binary!r} not found on PATH - install Wireshark/tshark"
        ) from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError as exc:
        proc.kill()
        with suppress_terminated_pipe():
            await proc.wait()
        raise TsharkTimeoutError(
            f"{binary} {' '.join(args[:2])}... timed out after {timeout}s"
        ) from exc

    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise TsharkError(
            f"{binary} exited {proc.returncode}: {truncate_output(stderr, 2000)}"
        )
    return truncate_output(stdout, max_output)
