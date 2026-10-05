"""Formatting/validation helpers for the metasploit MCP server (PLAN S1B.2).

Pure functions (plus a couple of ``rpc``-aware helpers for the console
drain and DB listing fallbacks) that turn raw RPC payloads into compact
Markdown for LLM consumption. All user-facing values pass through the
validators here before they reach :meth:`metasploit_mcp.rpc.MsfRPC.call`.
"""

from __future__ import annotations

import json
import re
import time
from contextlib import suppress
from typing import Any

from .rpc import MsfRPCError

__all__ = [
    "MAX_OUTPUT",
    "MODULE_TYPES",
    "check_md",
    "console_run",
    "db_list_md",
    "describe_options_md",
    "execute_md",
    "job_list_md",
    "module_info_md",
    "rank_name",
    "search_modules",
    "search_results_md",
    "session_list_md",
    "session_read",
    "session_write",
    "truncate",
    "validate_host_opts",
    "validate_identifier",
    "validate_module",
    "validate_uuid",
]

MAX_OUTPUT = 8_000

#: module types accepted by ``module.info/options/execute`` (case-sensitive)
MODULE_TYPES = ("exploit", "auxiliary", "post", "payload", "encoder", "evasion", "nop")

#: module names look like ``auxiliary/dos/http/slowloris``
MODULE_NAME_RE = re.compile(r"^[a-zA-Z0-9_+./-]+$")

#: session / job ids are small integers (accept int or digit string)
IDENT_RE = re.compile(r"^\d+$")

#: module.results UUIDs are hex with optional dashes
UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")

#: RHOSTS-style values: IPv4, IPv4/CIDR, IPv4 range, IPv6, IPv6/CIDR,
#: separated by commas or whitespace. Nothing else is allowed.
_IPV4_PART = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = rf"(?:{_IPV4_PART}\.){{3}}{_IPV4_PART}"
_HOST_TOKEN_RE = re.compile(
    rf"^(?:"
    rf"{_IPV4}(?:/(?:[0-9]|[12]\d|3[0-2]))?(?:-[0-9]{{1,3}})?"
    rf"|\[?[0-9a-fA-F:]+\]?(?:/(?:[0-9]|[1-9]\d|1[01]\d|12[0-8]))?"
    rf")$"
)

#: metasploit module ranks (int from old RPC, string from new RPC)
_RANKS = {
    0: "Manual",
    1: "Low",
    2: "Average",
    3: "Normal",
    4: "Good",
    5: "Great",
    6: "Excellent",
}
_RANK_NAMES = {name.lower(): name for name in _RANKS.values()}

#: columns shown per db.* listing
_DB_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "hosts": [
        ("address", "Address"),
        ("name", "Name"),
        ("os_name", "OS"),
        ("arch", "Arch"),
        ("purpose", "Purpose"),
        ("state", "State"),
        ("info", "Info"),
    ],
    "services": [
        ("host", "Host"),
        ("port", "Port"),
        ("proto", "Proto"),
        ("name", "Name"),
        ("state", "State"),
        ("info", "Info"),
    ],
    "vulns": [
        ("host", "Host"),
        ("name", "Name"),
        ("refs", "Refs"),
        ("info", "Info"),
    ],
    "notes": [
        ("host", "Host"),
        ("type", "Type"),
        ("data", "Data"),
    ],
}


def truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    """Return *text* capped to *limit* chars as head + tail + explicit marker."""
    if len(text) <= limit:
        return text
    if limit < 40:
        return f"[... {len(text)} chars truncated ...]"
    keep = limit - 40
    head = keep // 2
    tail = keep - head
    return (
        f"{text[:head]}\n[... {len(text) - keep} chars truncated ...]\n{text[-tail:]}"
    )


def _cell(value: Any, limit: int = 120) -> str:
    """Render one table cell: flatten dicts/lists to compact JSON."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return truncate(json.dumps(value, default=str, ensure_ascii=True)[:limit])
    text = str(value).replace("\n", " ").replace("|", "\\|").strip()
    return text[:limit]


def _rows_md(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "*none*"
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return "\n".join(lines)


def rank_name(rank: Any) -> str:
    """Map a metasploit rank (int or its string form) to its human name."""
    if isinstance(rank, str) and rank.strip().lower() in _RANK_NAMES:
        return _RANK_NAMES[rank.strip().lower()]
    try:
        return _RANKS.get(int(str(rank).strip('"')), str(rank))
    except (TypeError, ValueError):
        return str(rank)


# ---------------------------------------------------------------------------
# validation (reject anything that could smuggle commands or break framing)
# ---------------------------------------------------------------------------


def validate_module(mtype: str, mname: str) -> None:
    """Raise ValueError unless (mtype, mname) looks like a safe module ref."""
    if mtype not in MODULE_TYPES:
        raise ValueError(
            f"unknown module type {mtype!r}; expected one of {', '.join(MODULE_TYPES)}"
        )
    if (
        ".." in mname
        or mname.startswith("/")
        or mname.endswith("/")
        or "//" in mname
        or not MODULE_NAME_RE.fullmatch(mname)
    ):
        raise ValueError(
            f"invalid module name {mname!r}: only [a-zA-Z0-9_+./-] characters allowed"
        )
    if len(mname) > 200:
        raise ValueError("module name too long")


def validate_identifier(label: str, value: Any) -> str:
    """Validate a numeric id (session/job/console) and return it as a string."""
    text = str(value)
    if not IDENT_RE.fullmatch(text):
        raise ValueError(f"invalid {label} {value!r}: numeric id expected")
    return text


def validate_uuid(value: str) -> str:
    """Validate a module.results UUID."""
    text = str(value)
    if not UUID_RE.fullmatch(text):
        raise ValueError(f"invalid uuid {value!r}: hex/dash string expected")
    return text


def _hostish(key: str) -> bool:
    return key.lower() in {"rhost", "rhosts"}


def validate_host_opts(opts: dict[str, Any]) -> None:
    """Raise ValueError when a RHOSTS-style value contains anything other
    than IP/CIDR/range tokens (commas/whitespace separated)."""
    for key, value in opts.items():
        if not _hostish(key):
            continue
        text = str(value)
        tokens = [t for t in re.split(r"[,\s]+", text) if t]
        for token in tokens:
            if not _HOST_TOKEN_RE.fullmatch(token):
                raise ValueError(
                    f"{key} contains disallowed token {token!r}: "
                    f"IP / CIDR / range tokens only"
                )


# ---------------------------------------------------------------------------
# module search / info / options
# ---------------------------------------------------------------------------


def _has_msf_search_operators(query: str) -> bool:
    """True when the query uses metasploit search operators (``cve:2021``,
    ``type:exploit``, ``platform:windows``, ``name:...``, ``author:...``)."""
    return bool(
        re.search(r"(?:^|\s)[a-zA-Z_][a-zA-Z0-9_]*:", (query or "").strip())
    )


def search_modules(raw: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Rank *raw* module.search results against *query*.

    For plain-text queries the results are filtered + ranked client-side:
    exact fullname match > fullname/name prefix > contains > description
    contains; ties keep the server's original ordering.

    Queries that use metasploit's search syntax (``cve:2021 type:exploit``
    etc.) are left untouched: the server has already applied those filters,
    and a client-side literal substring check would wrongly wipe every hit
    (no module name or description contains the raw operator string).
    """
    q = (query or "").strip().lower()
    if not q:
        return list(raw)
    if _has_msf_search_operators(q):
        return list(raw)

    def _score(module: dict[str, Any]) -> int:
        fullname = str(module.get("fullname", "")).lower()
        name = str(module.get("name", "")).lower()
        description = str(module.get("description", "")).lower()
        if fullname == q:
            return 4
        if fullname.startswith(q) or fullname.endswith(q):
            return 3
        if name and (q in name or name in q):
            return 2
        if q in description:
            return 1
        return 0

    hits = [m for m in raw if _score(m) > 0]
    hits.sort(key=lambda m: (-_score(m),))
    return hits


def search_results_md(modules: list[dict[str, Any]], query: str) -> str:
    """Markdown list of search results: fullname (rank) — description."""
    if not modules:
        return f"*no modules match {query or '<empty query>'}*"
    lines = []
    for m in modules:
        fullname = str(m.get("fullname") or m.get("name") or "?")
        rank = rank_name(m.get("rank"))
        desc = _cell(m.get("description", ""), 200)
        lines.append(
            f"- **`{fullname}`** (rank: {rank}){(' — ' + desc) if desc else ''}"
        )
    return f"**{len(modules)} module(s) matching {query or '<all>'}:**\n" + "\n".join(
        lines
    )


def module_info_md(info: dict[str, Any]) -> str:
    """Render module.info payload as compact markdown."""
    labels: list[tuple[str, str]] = [
        ("name", "Name"),
        ("fullname", "Full name"),
        ("type", "Type"),
        ("description", "Description"),
        ("license", "License"),
        ("disclosuredate", "Disclosed"),
        ("rank", "Rank"),
        ("filepath", "File"),
    ]
    lines: list[str] = []
    for key, label in labels:
        value = info.get(key)
        if value is None or value == "" or value == []:
            continue
        if key == "rank":
            value = rank_name(value)
        lines.append(f"- **{label}:** {_cell(value, 400)}")

    def _refs(refs: Any) -> str:
        if not isinstance(refs, list):
            return _cell(refs, 200)
        parts: list[str] = []
        for ref in refs:
            if isinstance(ref, list) and len(ref) == 2:
                kind, ident = ref[0], ref[1]
                prefix = "URL" if str(kind).upper() == "URL" else f"{kind}-"
                parts.append(f"{prefix}{ident}" if kind != "URL" else str(ident))
            else:
                parts.append(str(ref))
        return ", ".join(parts)

    refs = info.get("references")
    if refs:
        lines.append(f"- **References:** {_refs(refs)}")
    for key, label in (
        ("authors", "Authors"),
        ("arch", "Arch"),
        ("platform", "Platforms"),
        ("targets", "Targets"),
    ):
        value = info.get(key)
        if isinstance(value, list) and value:
            lines.append(f"- **{label}:** {', '.join(str(v) for v in value)}")
    known = {
        "name",
        "fullname",
        "type",
        "description",
        "license",
        "disclosuredate",
        "rank",
        "filepath",
        "references",
        "authors",
        "arch",
        "platform",
        "targets",
    }
    extra = {
        k: v for k, v in info.items() if k not in known and v not in (None, "", [], {})
    }
    if extra:
        lines.append(
            "- **Extra:** "
            + ", ".join(f"{k}={_cell(v, 80)}" for k, v in sorted(extra.items()))
        )
    return "\n".join(lines)


def _required(opt: dict[str, Any]) -> str:
    req = opt.get("required")
    if req in (True, "true", "True", "1", 1):
        return "yes"
    return ""


def describe_options_md(options: dict[str, Any]) -> str:
    """Render module.options payload as a markdown table.

    Legacy metasploit returns uppercase option names (``RHOSTS``), newer
    frameworks lowercase ones (``rhost``); both are handled generically.
    """
    if not options:
        return "*module has no options*"
    rows: list[list[str]] = []
    for name, spec in options.items():
        if not isinstance(spec, dict):
            rows.append([str(name), "", "", _cell(spec, 60), "", ""])
            continue
        enums = spec.get("enums")
        choices = (
            ", ".join(str(e) for e in enums)
            if isinstance(enums, list) and enums
            else ""
        )
        rows.append(
            [
                str(name),
                _required(spec),
                _cell(spec.get("type"), 20),
                _cell(spec.get("default"), 40),
                _cell(choices, 60),
                _cell(spec.get("desc", spec.get("description", "")), 200),
            ]
        )
    rows.sort(key=lambda r: (r[1] != "yes", r[0].lower()))
    return _rows_md(
        ["Option", "Req", "Type", "Default", "Choices", "Description"], rows
    )


# ---------------------------------------------------------------------------
# sessions / jobs / db listings
# ---------------------------------------------------------------------------


def session_list_md(sessions: Any) -> str:
    """Render session.list payload (dict keyed by id, or list)."""
    if isinstance(sessions, dict):
        items = sorted(sessions.items(), key=lambda kv: str(kv[0]))
    elif isinstance(sessions, list):
        items = [
            (s.get("id") or s.get("sid"), s) for s in sessions if isinstance(s, dict)
        ]
    else:
        return "*no sessions*"
    if not items:
        return "*no sessions*"
    rows: list[list[str]] = []
    for sid, s in items:
        info = s if isinstance(s, dict) else {}
        peer = (
            info.get("tunnel_peer")
            or info.get("session_host")
            or info.get("host")
            or ""
        )
        rows.append(
            [
                str(sid),
                _cell(info.get("type", "")),
                _cell(peer),
                _cell(info.get("platform", ""), 20),
                _cell(info.get("via_exploit") or info.get("desc", ""), 80),
            ]
        )
    return _rows_md(["ID", "Type", "Peer", "Platform", "Via/Desc"], rows)


def job_list_md(jobs: Any) -> str:
    """Render job.list payload (dict keyed by id -> name)."""
    if isinstance(jobs, dict):
        items = sorted(jobs.items(), key=lambda kv: str(kv[0]))
    elif isinstance(jobs, list):
        items = [(j.get("jid"), j.get("name", "")) for j in jobs if isinstance(j, dict)]
    else:
        return "*no jobs*"
    if not items:
        return "*no jobs*"
    rows = [[str(sid), _cell(name, 200)] for sid, name in items]
    return _rows_md(["ID", "Name"], rows)


def _db_unwrap(payload: Any, kind: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get(kind), list):
            return [p for p in payload[kind] if isinstance(p, dict)]
        for value in payload.values():  # {workspace: {kind: [...]}} style
            if isinstance(value, dict) and isinstance(value.get(kind), list):
                return [p for p in value[kind] if isinstance(p, dict)]
    return []


def _db_unavailable(kind: str, error: MsfRPCError) -> None:
    """Re-raise with a friendly message when the msfrpcd DB is unavailable."""
    if "database" not in str(error).lower():
        raise error
    raise MsfRPCError(
        f"db.{kind} unavailable: the msfrpcd database is not loaded "
        f"(started with -n or no workspace?) — {error}"
    ) from error


def db_list_md(rpc: Any, kind: str) -> str:
    """Fetch and render a ``db.<kind>`` listing.

    Legacy msfrpcd accepts no arguments; modern v10 requires an options
    hash — retried with ``{}`` on the "wrong number of arguments" error.
    """
    columns = _DB_COLUMNS.get(
        kind, [("host", "Host"), ("name", "Name"), ("info", "Info")]
    )
    try:
        payload = rpc.call(f"db.{kind}")
    except MsfRPCError as e:
        if "wrong number of arguments" not in str(e).lower():
            _db_unavailable(kind, e)
        try:
            payload = rpc.call(f"db.{kind}", {})
        except MsfRPCError as e2:
            _db_unavailable(kind, e2)
    rows_raw = _db_unwrap(payload, kind)
    rows: list[list[str]] = []
    for item in rows_raw:
        refs = item.get("refs")
        if isinstance(refs, list):
            item["refs"] = ", ".join(
                str(r[1] if isinstance(r, list) and len(r) == 2 else r) for r in refs
            )
        rows.append([_cell(item.get(key, ""), 160) for key, _ in columns])
    headers = [label for _, label in columns]
    if not rows_raw:
        return f"*db.{kind}: no entries*"
    return f"**db.{kind} ({len(rows_raw)}):**\n" + _rows_md(headers, rows)


# ---------------------------------------------------------------------------
# sessions: read/write with cross-version fallbacks
# ---------------------------------------------------------------------------

_SESSION_READ_METHODS = (
    "session.read",
    "session.shell_read",
    "session.ring_read",
    "session.interactive_read",
)
_SESSION_WRITE_METHODS = (
    "session.write",
    "session.shell_write",
    "session.meterpreter_write",
    "session.interactive_write",
)


def _retryable(e: Exception) -> bool:
    text = str(e).lower()
    return any(
        marker in text
        for marker in (
            "unknown api call",
            "invalid session type",
            "session disconnected",
            "wrong number of arguments",
        )
    )


def session_read(rpc: Any, session_id: str) -> str:
    """Read a session's output; tries legacy + modern method names."""
    last_error: MsfRPCError | None = None
    for method in _SESSION_READ_METHODS:
        try:
            payload = rpc.call(method, session_id)
            break
        except MsfRPCError as e:
            if not _retryable(e):
                raise
            last_error = e
    else:
        raise MsfRPCError(
            f"cannot read session {session_id}: {last_error}"
        ) from last_error
    if isinstance(payload, dict):
        data = payload.get("data")
        if data is None:
            data = payload.get("output")
        if data is None:
            data = _cell(payload, 400)
        text = str(data)
    else:
        text = str(payload)
    return truncate(text)


def session_write(rpc: Any, session_id: str, data: str) -> str:
    """Write *data* to a session (no trailing newline is added)."""
    if not isinstance(data, str) or not data:
        raise ValueError("session data must be a non-empty string")
    if len(data) > 8_192:
        raise ValueError("session data too long (max 8192 chars)")
    last_error: MsfRPCError | None = None
    for method in _SESSION_WRITE_METHODS:
        try:
            payload = rpc.call(method, session_id, data)
            break
        except MsfRPCError as e:
            if not _retryable(e):
                raise
            last_error = e
    else:
        raise MsfRPCError(
            f"cannot write session {session_id}: {last_error}"
        ) from last_error
    return f"session {session_id} write OK: {_cell(payload, 200)}"


# ---------------------------------------------------------------------------
# ephemeral console (msf_console_run)
# ---------------------------------------------------------------------------


def console_run(
    rpc: Any,
    command: str,
    *,
    timeout: float = 120.0,
    poll_interval: float = 0.25,
    max_chunks: int = 2_000,
) -> str:
    """Run *command* on an ephemeral console; return its output (truncated).

    The console is created, the command written (newline appended), output
    drained until the ``msf6`` prompt or a quiet period, then destroyed —
    even on errors.
    """
    if not command.strip():
        raise ValueError("console command must not be empty")
    if len(command) > 4_000:
        raise ValueError("console command too long (max 4000 chars)")
    created = rpc.call("console.create")
    console_id = str(
        created.get("id", created if isinstance(created, (int, str)) else "")
    )
    if not console_id:
        raise MsfRPCError(f"console.create returned no id: {_cell(created, 200)}")
    chunks: list[str] = []
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        rpc.call("console.write", console_id, f"{command}\n")
        while time.monotonic() < deadline:
            chunk = rpc.call("console.read", console_id)
            data = str(chunk.get("data", "") if isinstance(chunk, dict) else chunk)
            if data:
                chunks.append(data)
            if len(chunks) > max_chunks:
                break
            busy = chunk.get("busy", False) if isinstance(chunk, dict) else False
            if not busy:
                prompt = chunk.get("prompt", "") if isinstance(chunk, dict) else ""
                text = chunks[-1].lower() if chunks else ""
                at_prompt = (
                    "msf6" in text or ("msf" in text and ">" in text[-60:])
                ) or ">" in text[-1:]
                if at_prompt or "msf6" in str(prompt).lower():
                    time.sleep(0.2)  # flush stragglers
                    tail = rpc.call("console.read", console_id)
                    tail_data = str(
                        tail.get("data", "") if isinstance(tail, dict) else tail
                    )
                    if tail_data:
                        chunks.append(tail_data)
                    break
            time.sleep(poll_interval)
        else:
            timed_out = True
    finally:
        with suppress(MsfRPCError):
            rpc.call("console.destroy", console_id)
    output = "".join(chunks)
    if timed_out:
        output += (
            f"\n[... console still busy after {timeout:.0f}s; output truncated ...]"
        )
    return truncate(output)


# ---------------------------------------------------------------------------
# module execute / check / results result rendering
# ---------------------------------------------------------------------------


def _kv_lines(payload: Any, order: tuple[str, ...] = ()) -> str:
    """Render an RPC result dict as deterministic markdown lines."""
    if not isinstance(payload, dict):
        return _cell(payload, 2_000)
    lines: list[str] = []
    seen: set[str] = set()
    for key in (*order, *(k for k in sorted(payload) if k not in order)):
        if key in seen or payload.get(key) in (None, "", [], {}):
            continue
        seen.add(key)
        lines.append(f"- **{key}:** {_cell(payload.get(key), 400)}")
    return "\n".join(lines)


def execute_md(payload: Any) -> str:
    """Render module.execute result (job_id + uuid; possibly a result map)."""
    if isinstance(payload, dict) and ("job_id" in payload or "uuid" in payload):
        return _kv_lines(payload, order=("job_id", "uuid", "status", "result"))
    return _kv_lines(payload, order=("status", "result"))


def check_md(payload: Any) -> str:
    """Render module.check result (modern: {status, result}; legacy variants)."""
    return _kv_lines(
        payload, order=("status", "result", "code", "checkcode", "message")
    )
