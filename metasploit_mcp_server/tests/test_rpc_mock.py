"""Client + helper tests against a mocked msgpack/HTTP layer (PLAN S1B.4).

The transport mock replays *recorded* msfrpcd hashes (see conftest.py)
instead of opening a socket, so login/token-refresh/arg-building/error
paths are exercised deterministically without Metasploit installed.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import msgpack
import pytest

from metasploit_mcp import helpers
from metasploit_mcp import (
    server as msf_server,  # noqa: F401  (sanity: server imports cleanly)
)
from metasploit_mcp.rpc import (
    DEFAULT_PORT,
    MsfRPC,
    MsfRPCAuthError,
    MsfRPCConfigError,
    MsfRPCError,
    ensure_daemon,
    from_env,
    sanitize_module_opts,
    sanitize_option_value,
)

from .conftest import msf_live


class ReplayRPC(MsfRPC):
    """MsfRPC whose transport answers from recorded hashes instead of HTTP.

    ``labels`` maps RPC method names to recorded-fixture labels; the
    recorded payload is re-packed so the client decodes it exactly like a
    real msfrpcd response.
    """

    def __init__(
        self,
        recordings: dict[str, list],
        labels: Callable[[str, tuple], str] | dict[str, str],
        *,
        password: str = "scratchpass",
    ) -> None:
        super().__init__(password=password, ssl_enabled=False)
        self.recordings = recordings
        self._labels = labels
        self.sent: list[list] = []  # every unpacked request payload

    def _label(self, method: str, args: tuple) -> str:
        if callable(self._labels):
            return self._labels(method, args)
        if method in self._labels:
            return self._labels[method]
        if method == "auth.login":
            return "auth.login_ok"
        return method

    def _transact(self, payload: bytes, timeout: float | None = None):
        self.last_timeout = timeout
        unpacked = msgpack.unpackb(payload, raw=False)
        self.sent.append(unpacked)
        method = str(unpacked[0])
        args = tuple(unpacked[2:] if len(unpacked) > 2 else ())
        code, value = self.recordings[self._label(method, args)]
        return int(code), msgpack.packb(value)


def make_rpc(
    recordings: dict[str, list],
    labels: Any | None = None,
    *,
    password: str = "scratchpass",
) -> ReplayRPC:
    return ReplayRPC(
        recordings, labels if labels is not None else {}, password=password
    )


# ---------------------------------------------------------------------------
# auth + token lifecycle
# ---------------------------------------------------------------------------


def test_login_success_parses_token(recorded_rpc):
    rpc = make_rpc(recorded_rpc, {"auth.login": "auth.login_ok"})
    token = rpc.login()
    assert token.startswith("TEMP")
    assert rpc.authenticated
    assert rpc.sent == [["auth.login", "msf", "scratchpass"]]


def test_login_bad_password_raises_without_leaking_secret(recorded_rpc):
    rpc = make_rpc(
        recorded_rpc, {"auth.login": "auth.login_badpw"}, password="s3cret-pw"
    )
    with pytest.raises(MsfRPCAuthError) as exc:
        rpc.login()
    assert "s3cret-pw" not in str(exc.value)
    assert not rpc.authenticated


def test_call_autologins_when_no_token(recorded_rpc):
    rpc = make_rpc(
        recorded_rpc,
        {"auth.login": "auth.login_ok", "core.version": "core.version"},
    )
    info = rpc.call("core.version")
    assert info["version"] == "6.5.0-dev"
    assert isinstance(info["ruby"], str)  # decoded from msgpack bin -> str
    methods = [p[0] for p in rpc.sent]
    assert methods == ["auth.login", "core.version"]


def test_token_expiry_retriggers_login_once_and_retries(recorded_rpc):
    state = {"expired": True}

    def labels(method: str, _args: tuple) -> str:
        if method == "auth.login":
            return "auth.login_ok"
        if method == "core.version":
            if state["expired"]:
                state["expired"] = False
                return "bad_token_core"
            return "core.version"
        raise AssertionError(f"unexpected method {method}")

    rpc = make_rpc(recorded_rpc, labels)
    info = rpc.call("core.version")
    assert info["version"] == "6.5.0-dev"
    methods = [p[0] for p in rpc.sent]
    # login, first (expired) call, re-login, retry
    assert methods == ["auth.login", "core.version", "auth.login", "core.version"]


def test_remote_module_check_error_is_raised(recorded_rpc):
    rpc = make_rpc(recorded_rpc, {"module.check": "module.check_unsupported"})
    with pytest.raises(MsfRPCError):
        rpc.call("module.check", "auxiliary", "dos/http/slowloris", {})


def test_unknown_method_error_is_raised(recorded_rpc):
    rpc = make_rpc(recorded_rpc, {"core.bogus_method": "unknown_method"})
    with pytest.raises(MsfRPCError) as exc:
        rpc.call("core.bogus_method")
    assert "Unknown API Call" in str(exc.value) or "failed" in str(exc.value)


def test_context_manager_login_logout(recorded_rpc):
    rpc = make_rpc(
        recorded_rpc,
        {"auth.login": "auth.login_ok", "auth.logout": "auth.login_ok"},
    )
    with rpc as logged_in:
        assert logged_in.authenticated
    assert not rpc.authenticated


def test_login_legacy_array_response_token():
    """Old-style msfrpcd: auth.login answers ['success', '<token>']."""
    legacy = {"auth.login": [200, ["success", "LEGACYTOKEN"]]}
    rpc = make_rpc(legacy, {"auth.login": "auth.login"})
    assert rpc.login() == "LEGACYTOKEN"


def test_legacy_token_expiry_array_error_triggers_relogin(recorded_rpc):
    """Old-style daemons report bad tokens as HTTP-200 error arrays; the
    marker substring must still trigger the one-shot re-login + retry."""
    state = {"expired": True}

    class LegacyTransport(ReplayRPC):
        def _transact(self, payload: bytes, timeout: float | None = None):
            self.last_timeout = timeout
            unpacked = msgpack.unpackb(payload, raw=False)
            self.sent.append(unpacked)
            method = str(unpacked[0])
            if method == "core.version" and state["expired"]:
                state["expired"] = False
                return 200, msgpack.packb(
                    ["error", "Invalid authentication token", "core.version", []]
                )
            code, value = self.recordings[self._label(method, ())]
            return int(code), msgpack.packb(value)

    rpc = LegacyTransport(recorded_rpc, {"auth.login": "auth.login_ok"})
    info = rpc.call("core.version")
    assert info["version"] == "6.5.0-dev"
    methods = [p[0] for p in rpc.sent]
    assert methods == ["auth.login", "core.version", "auth.login", "core.version"]


def test_logout_payload_carries_token_for_auth_and_argument(recorded_rpc):
    rpc = make_rpc(
        recorded_rpc,
        {
            "auth.login": "auth.login_ok",
            "auth.logout": "console.destroy",  # {'result': 'success'}
        },
    )
    with rpc as logged_in:
        token = logged_in.login()
    assert not rpc.authenticated
    logout_payload = rpc.sent[-1]
    assert logout_payload == ["auth.logout", token, token]


def test_scalar_and_invalid_msgpack_responses():
    class RawTransport(MsfRPC):
        def __init__(self, responses):
            super().__init__(password="pw", ssl_enabled=False)
            self.responses = list(responses)
            self.sent = []

        def _transact(self, payload, timeout=None):
            self.last_timeout = timeout
            self.sent.append(msgpack.unpackb(payload, raw=False))
            return self.responses.pop(0)

    scalar = RawTransport(
        [
            (200, msgpack.packb({"result": "success", "token": "T1"})),
            (200, msgpack.packb("plain-text-result")),
        ]
    )
    assert scalar.call("core.version") == "plain-text-result"

    integer = RawTransport(
        [
            (200, msgpack.packb({"result": "success", "token": "T1"})),
            (200, msgpack.packb(42)),
        ]
    )
    assert integer.call("core.version") == 42

    corrupt = RawTransport(
        [
            (200, msgpack.packb({"result": "success", "token": "T1"})),
            (200, b"\xc1\xc1\xc1"),  # not valid msgpack
        ]
    )
    with pytest.raises(MsfRPCError, match="invalid msgpack"):
        corrupt.call("core.version")

    http_error = RawTransport(
        [
            (200, msgpack.packb({"result": "success", "token": "T1"})),
            (503, b"<html>gateway timeout</html>"),  # non-msgpack HTTP error
        ]
    )
    with pytest.raises(MsfRPCError) as exc:
        http_error.call("core.version")
    assert exc.value.code == 503  # HTTP status preserved on the exception


# ---------------------------------------------------------------------------
# recorded payload replay (real daemon hashes)
# ---------------------------------------------------------------------------


def test_replayed_search_returns_slowloris_module(recorded_rpc):
    """Replays the real msfrpcd answer for module.search 'slowloris'."""
    rpc = make_rpc(recorded_rpc, {"module.search": "module.search_slowloris"})
    results = rpc.call("module.search", "slowloris")
    assert isinstance(results, list) and results
    assert results[0]["fullname"] == "auxiliary/dos/http/slowloris"
    assert results[0]["type"] == "auxiliary"


def test_replayed_module_info_and_options(recorded_rpc):
    rpc = make_rpc(
        recorded_rpc,
        {
            "module.info": "module.info_slowloris",
            "module.options": "module.options_slowloris",
        },
    )
    info = rpc.call("module.info", "auxiliary", "dos/http/slowloris")
    assert info["name"] == "Slowloris Denial of Service Attack"
    assert isinstance(info["references"], list)
    options = rpc.call("module.options", "auxiliary", "dos/http/slowloris")
    assert any(key.lower() in {"rhost", "rhosts"} for key in options)


def test_replayed_core_version_and_empty_lists(recorded_rpc):
    rpc = make_rpc(
        recorded_rpc,
        {
            "session.list": "session.list",
            "job.list": "job.list",
            "db.hosts": "db.hosts",  # modern daemon errors: expects opts arg
        },
    )
    assert rpc.call("session.list") == {}
    assert rpc.call("job.list") == {}
    with pytest.raises(MsfRPCError) as exc:
        rpc.call("db.hosts")
    assert "wrong number of arguments" in str(exc.value).lower()


def test_console_lifecycle_replay(recorded_rpc):
    rpc = make_rpc(
        recorded_rpc,
        {
            "console.create": "console.create",
            "console.write": "console.write_version",
            "console.read": "console.read_after",
            "console.destroy": "console.destroy",
        },
    )
    created = rpc.call("console.create")
    assert created["id"] == "0"
    assert rpc.call("console.write", "0", "version\n")["wrote"] == 8
    read = rpc.call("console.read", "0")
    assert "data" in read and "busy" in read
    assert rpc.call("console.destroy", "0") == {}


# ---------------------------------------------------------------------------
# option sanitization (CVE-2026-5463 mitigation)
# ---------------------------------------------------------------------------


def test_sanitize_option_value_strips_newlines_and_nul():
    assert sanitize_option_value("a\nb\rc\x00d") == "a b cd"  # NUL removed
    assert sanitize_option_value("clean") == "clean"


def test_sanitize_option_value_passes_non_strings():
    assert sanitize_option_value(80) == 80
    assert sanitize_option_value(True) is True
    assert sanitize_option_value(None) is None
    assert sanitize_option_value(["x\n"]) == ["x\n"]  # lists untouched


def test_sanitize_module_opts_strips_every_string_value():
    opts = sanitize_module_opts(
        {
            "RHOSTS": "10.0.0.5",
            "RPORT": 80,
            "TARGETURI": "/x\r\nquit",
            "PAYLOAD": "cmd/unix/reverse\rX",
        }
    )
    assert opts["RHOSTS"] == "10.0.0.5"
    assert opts["RPORT"] == 80
    assert opts["TARGETURI"] == "/x quit"
    assert opts["PAYLOAD"] == "cmd/unix/reverse X"
    assert "\n" not in "".join(str(v) for v in opts.values())


def test_newline_never_reaches_the_wire(recorded_rpc):
    rpc = make_rpc(recorded_rpc, {"module.execute": "unknown_method"})
    with pytest.raises(MsfRPCError):
        rpc.call("module.execute", "auxiliary", "x", {"TARGETURI": "a\nb"})
    sent = msgpack.unpackb(msgpack.packb(rpc.sent[-1]), raw=False)
    assert "\n" not in str(sent)


# ---------------------------------------------------------------------------
# config / daemon management
# ---------------------------------------------------------------------------


def test_from_env_requires_password(monkeypatch):
    monkeypatch.delenv("MSF_RPC_PASS", raising=False)
    monkeypatch.delenv("MSF_RPC_HOST", raising=False)
    monkeypatch.delenv("MSF_RPC_PORT", raising=False)
    with pytest.raises(MsfRPCConfigError):
        from_env()


def test_from_env_parses_all_vars(monkeypatch):
    monkeypatch.setenv("MSF_RPC_PASS", "pw")
    monkeypatch.setenv("MSF_RPC_HOST", "10.9.9.9")
    monkeypatch.setenv("MSF_RPC_PORT", "55553")
    monkeypatch.setenv("MSF_RPC_USER", "alice")
    monkeypatch.setenv("MSF_RPC_SSL", "no")
    rpc = from_env()
    assert rpc.password == "pw"
    assert rpc.host == "10.9.9.9"
    assert rpc.port == 55553
    assert rpc.user == "alice"
    assert rpc.ssl_enabled is False


def test_from_env_rejects_non_integer_port(monkeypatch):
    monkeypatch.setenv("MSF_RPC_PASS", "pw")
    monkeypatch.setenv("MSF_RPC_PORT", "abc")
    with pytest.raises(MsfRPCConfigError):
        from_env()


@pytest.mark.parametrize("bad", ["abc", "1e", "", "-1", "0"])
def test_from_env_rejects_bad_timeout(monkeypatch, bad: str):
    monkeypatch.setenv("MSF_RPC_PASS", "pw")
    monkeypatch.setenv("MSF_RPC_TIMEOUT", bad)
    with pytest.raises(MsfRPCConfigError):
        from_env()


def test_from_env_accepts_float_timeout(monkeypatch):
    monkeypatch.setenv("MSF_RPC_PASS", "pw")
    monkeypatch.setenv("MSF_RPC_TIMEOUT", "7.5")
    assert from_env().timeout == 7.5


@pytest.mark.parametrize(
    "value,default,expected",
    [
        ("1", False, True),
        ("TRUE", False, True),
        ("Yes", False, True),
        ("on", False, True),
        ("0", True, False),
        ("off", True, False),
        ("", True, True),
        (None, True, True),
    ],
)
def test_env_flag_parsing(value, default: bool, expected: bool):
    from metasploit_mcp.rpc import env_flag

    assert env_flag(value, default) is expected


def test_redact_password_never_enters_logs(monkeypatch, caplog):
    import logging

    from metasploit_mcp import rpc as rpc_mod

    spawned: list[list[str]] = []

    class DeadProc:
        returncode = 1

        def poll(self) -> int:
            return 1

    def fake_popen(cmd, **_kw):
        spawned.append(cmd)
        return DeadProc()

    monkeypatch.setattr(rpc_mod.shutil, "which", lambda _: "/fake/msfrpcd")
    monkeypatch.setattr(rpc_mod.subprocess, "Popen", fake_popen)
    with (
        caplog.at_level(logging.INFO, logger="metasploit_mcp.rpc"),
        pytest.raises(MsfRPCError, match="exited during startup"),
    ):
        rpc_mod.ensure_daemon(password="SUPERSECRET", host="127.0.0.1", port=1)
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "SUPERSECRET" not in log_text
    assert "***" in log_text
    # ... and the spawned argv still carries the real password
    assert spawned[0][spawned[0].index("-P") + 1] == "SUPERSECRET"


def test_ensure_daemon_skips_when_port_already_listening(monkeypatch):
    import socket
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def close_later() -> None:
        stop.wait(5)
        listener.close()

    threading.Thread(target=close_later, daemon=True).start()
    try:

        def boom(*_a, **_k):
            raise AssertionError("must not spawn when the port is open")

        monkeypatch.setattr("metasploit_mcp.rpc.subprocess.Popen", boom)
        ensure_daemon(password="pw", host="127.0.0.1", port=port, start_timeout=0.5)
    finally:
        stop.set()


def test_ensure_daemon_reports_start_timeout(monkeypatch):
    from metasploit_mcp import rpc as rpc_mod

    class AliveProc:
        def poll(self) -> None:
            return None

    def fake_popen(*_a, **_k):
        return AliveProc()

    def always_closed(*_a, **_k):
        return False

    monkeypatch.setattr(rpc_mod.shutil, "which", lambda _: "/fake/msfrpcd")
    monkeypatch.setattr(rpc_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(rpc_mod, "port_open", always_closed)
    with pytest.raises(MsfRPCError, match="did not listen"):
        ensure_daemon(
            password="pw",
            host="127.0.0.1",
            port=55553,
            start_timeout=0.1,
            poll_interval=0.01,
        )


def test_ensure_daemon_spawns_when_port_closed_but_reports_early_exit(
    monkeypatch,
):
    spawned: list[list[str]] = []
    monkeypatch.setattr("metasploit_mcp.rpc.shutil.which", lambda _: "/fake/msfrpcd")

    class DeadProc:
        returncode = 1

        def poll(self) -> int:
            return 1

    def fake_popen(cmd, **_kw):
        spawned.append(cmd)
        return DeadProc()

    monkeypatch.setattr("metasploit_mcp.rpc.subprocess.Popen", fake_popen)
    with pytest.raises(MsfRPCError) as exc:
        ensure_daemon(password="pw", host="127.0.0.1", port=1)  # nothing listens
    assert spawned, "expected a spawn attempt when the port is closed"
    assert "exited during startup" in str(exc.value)


def test_ensure_daemon_spawns_msfrpcd_with_safe_flags(monkeypatch):
    calls = {"popen": 0}
    captured: dict = {}

    def fake_which(_name: str) -> str:
        return "/fake/msfrpcd"

    class FakeProc:
        def poll(self) -> None:
            return None

    def fake_popen(cmd, **kw) -> FakeProc:
        calls["popen"] += 1
        captured["cmd"] = cmd
        captured["start_new_session"] = kw.get("start_new_session")
        captured["stderr_none"] = kw.get("stderr") is None
        return FakeProc()

    monkeypatch.setattr("metasploit_mcp.rpc.shutil.which", fake_which)
    monkeypatch.setattr("metasploit_mcp.rpc.subprocess.Popen", fake_popen)

    seq = {"n": 0}

    def fake_port_open(_host: str, _port: int, _timeout: float = 1.0) -> bool:
        seq["n"] += 1
        return seq["n"] >= 2  # closed at first check, open after spawn

    monkeypatch.setattr("metasploit_mcp.rpc.port_open", fake_port_open)
    ensure_daemon(password="pw", host="127.0.0.1", port=55553, ssl_enabled=False)
    cmd = captured["cmd"]
    assert cmd[0] == "/fake/msfrpcd"
    assert "-P" in cmd and cmd[cmd.index("-P") + 1] == "pw"
    assert "-n" in cmd and "-f" in cmd and "-S" in cmd  # no DB, foreground, no SSL
    assert captured["start_new_session"] is True
    assert captured["stderr_none"] is True  # logs to stderr


def test_ensure_daemon_refuses_remote_host(monkeypatch):
    monkeypatch.setattr("metasploit_mcp.rpc.port_open", lambda *_a, **_k: False)
    with pytest.raises(MsfRPCError) as exc:
        ensure_daemon(password="pw", host="192.168.1.10", port=55553)
    assert "loopback" in str(exc.value)


def test_client_connection_refused_message():
    rpc = MsfRPC(password="pw", host="127.0.0.1", port=1, ssl_enabled=False)
    rpc._token = "tok"
    with pytest.raises(MsfRPCError) as exc:
        rpc.call("core.version")
    assert "unreachable" in str(exc.value) or "refused" in str(exc.value)


def test_url_properties():
    rpc = MsfRPC(password="pw", ssl_enabled=True)
    assert rpc.url == f"https://127.0.0.1:{DEFAULT_PORT}/api/"
    rpc_nossl = MsfRPC(password="pw", ssl_enabled=False)
    assert rpc_nossl.url == f"http://127.0.0.1:{DEFAULT_PORT}/api/"


# ---------------------------------------------------------------------------
# helpers: validation
# ---------------------------------------------------------------------------


def test_validate_module_accepts_known_types_and_names():
    helpers.validate_module("auxiliary", "dos/http/slowloris")
    helpers.validate_module("exploit", "multi/handler")
    helpers.validate_module("post", "multi/gather/env")


def test_validate_module_rejects_injection_names():
    for mname in ("aux;x", "..", "../evil", "aux\nx", "aux/$(id)", "a b"):
        with pytest.raises(ValueError):
            helpers.validate_module("auxiliary", mname)
    with pytest.raises(ValueError):
        helpers.validate_module("scanner", "dos/http/slowloris")


def test_validate_identifier_and_uuid():
    assert helpers.validate_identifier("session id", 3) == "3"
    assert helpers.validate_identifier("session id", "0") == "0"
    for bad in ("abc", "1;2", "-1", ""):
        with pytest.raises(ValueError):
            helpers.validate_identifier("session id", bad)
    assert helpers.validate_uuid("DEADBEEF-1234") == "DEADBEEF-1234"
    for bad in ("x" * 100, "ab;cd", ".."):
        with pytest.raises(ValueError):
            helpers.validate_uuid(bad)


@pytest.mark.parametrize(
    "key,value",
    [
        ("RHOSTS", "10.0.0.5"),
        ("RHOSTS", "10.0.0.5,10.0.0.6"),
        ("RHOSTS", "10.0.0.0/24 10.0.1.1-20"),
        ("rhost", "fd00::1"),
        ("RHOSTS", "192.168.1.5,10.0.0.0/8,10.0.0.1-255"),
        ("RHoStS", "10.0.0.1"),
    ],
)
def test_validate_host_opts_accepts_addresses(key, value):
    helpers.validate_host_opts({key: value})


@pytest.mark.parametrize(
    "key,value",
    [
        ("RHOSTS", ";rm -rf /"),
        ("RHOSTS", "$(curl evil)"),
        ("RHOSTS", "10.0.0.5;echo pwned"),
        ("RHOSTS", "10.0.0.5\nreboot"),
        ("RHOSTS", "`id`"),
        ("rhost", "10.0.0.5 | sh"),
        ("RHOSTS", "http://10.0.0.5/"),
        ("RHOSTS", "evil.com"),
    ],
)
def test_validate_host_opts_rejects_metacharacters(key, value):
    with pytest.raises(ValueError):
        helpers.validate_host_opts({key: value})


def test_validate_host_opts_ignores_non_host_keys():
    helpers.validate_host_opts({"TARGETURI": "/x;y", "CMD": "reboot\n"})
    assert True


# ---------------------------------------------------------------------------
# helpers: formatting
# ---------------------------------------------------------------------------


def test_truncate_head_tail_marker():
    text = "a" * 10_000
    cut = helpers.truncate(text)
    assert len(cut) <= 8_100
    assert "chars truncated" in cut
    assert cut.startswith("a" * 100) and cut.endswith("a" * 100)


def test_search_modules_ranking():
    raw = [
        {
            "fullname": "auxiliary/scanner/http/brute",
            "name": "x",
            "description": "brute slowloris scanner",
        },
        {"fullname": "exploit/x", "name": "slowloris helper"},
        {
            "fullname": "auxiliary/dos/http/slowloris",
            "name": "Slowloris DoS",
            "description": "slowloris attack",
        },
    ]
    hits = helpers.search_modules(raw, "slowloris")
    assert [h["fullname"] for h in hits] == [
        "auxiliary/dos/http/slowloris",  # fullname match first
        "exploit/x",  # name match
        "auxiliary/scanner/http/brute",  # description match
    ]
    assert helpers.search_modules(raw, "zzz-not-there") == []


def test_search_modules_passes_operator_queries_through_unchanged():
    """Metasploit search-operator queries (cve:/type:/platform:/... ) are
    already applied server-side; a client-side literal substring filter must
    not wipe the server's results (the operator string never appears in a
    module's name or description)."""
    raw = [
        {
            "fullname": "auxiliary/dos/http/slowloris",
            "name": "Slowloris DoS",
            "description": "slowloris keeps sockets open",
        },
        {"fullname": "exploit/multi/http/x", "name": "X", "description": "y"},
    ]
    for query in (
        "cve:2021-44228 type:exploit",
        "type:auxiliary name:slowloris",
        "platform:linux",
        "  author:rsnake  ",
        "cve:2021",
    ):
        kept = helpers.search_modules(raw, query)
        assert kept == raw, query  # order and membership preserved


def test_search_modules_plain_text_still_filters_and_ranks():
    raw = [
        {"fullname": "auxiliary/dos/http/slowloris", "description": "sockets"},
        {"fullname": "exploit/unrelated", "description": "sockets"},
    ]
    assert helpers.search_modules(raw, "slowloris") == [raw[0]]
    assert helpers.search_modules(raw, "type:exploit") == raw  # operator pass


def test_search_results_md_rendering():
    md = helpers.search_results_md(
        [{"fullname": "auxiliary/dos/http/slowloris", "rank": "normal"}], "slowloris"
    )
    assert "auxiliary/dos/http/slowloris" in md
    assert "Normal" in md
    assert "1 module(s)" in md
    assert "no modules match" in helpers.search_results_md([], "x")


def test_module_info_md_formats_references():
    md = helpers.module_info_md(
        {
            "name": "Slowloris",
            "description": "keeps sockets open",
            "rank": 3,
            "references": [["CVE", "2007-6750"], ["URL", "https://x.io"]],
            "authors": ["RSnake"],
            "platform": ["linux"],
            "default_options": {"x": 1},  # goes to Extra
        }
    )
    assert "**Name:** Slowloris" in md
    assert "CVE-2007-6750" in md
    assert "https://x.io" in md
    assert "RSnake" in md
    assert "**Rank:** Normal" in md


def test_describe_options_md_table():
    options = {
        "RHOSTS": {"type": "address", "required": True, "desc": "target"},
        "RPORT": {
            "type": "port",
            "required": True,
            "default": 80,
            "enums": [80, 443],
            "desc": "port",
        },
        "SSL": {"type": "bool", "required": False, "default": False},
    }
    md = helpers.describe_options_md(options)
    assert "| Option | Req | Type | Default | Choices | Description |" in md
    assert "RHOSTS" in md and "RPORT" in md
    assert "yes" in md.split("RHOSTS")[1][:80]
    assert "80" in md.split("RPORT")[1][:120]


def test_session_and_job_list_md():
    sessions = {
        "1": {
            "type": "shell",
            "tunnel_peer": "10.0.0.9:4444",
            "platform": "linux",
            "via_exploit": "exploit/multi/handler",
        },
    }
    md = helpers.session_list_md(sessions)
    assert "shell" in md and "10.0.0.9:4444" in md
    assert "no sessions" in helpers.session_list_md({})
    assert "no sessions" in helpers.session_list_md(None)
    jobs = {"0": "Exploit: multi/handler"}
    jmd = helpers.job_list_md(jobs)
    assert "Exploit: multi/handler" in jmd
    assert "no jobs" in helpers.job_list_md({})


# ---------------------------------------------------------------------------
# helpers: rpc-backed paths with mocked clients
# ---------------------------------------------------------------------------


class _StubRPC:
    """Minimal stand-in exposing call() with scripted per-method behavior."""

    def __init__(self, handlers=None):
        self.handlers = handlers or {}
        self.calls: list[tuple] = []

    def call(self, method, *args, **_kwargs):
        self.calls.append((method, args))
        handler = self.handlers.get(method)
        if isinstance(handler, Exception):
            raise handler
        if handler is not None:
            return handler(*args) if callable(handler) else handler
        return {"result": "success"}


def test_db_list_falls_back_to_opts_hash_for_modern_msf():
    modern_error = MsfRPCError(
        "metasploit db.hosts failed: wrong number of arguments (given 0, expected 1)"
    )
    calls: list[tuple] = []

    class ModernDB(_StubRPC):
        def __init__(self):
            self.n = 0

        def call(self, method, *args, **_kwargs):
            calls.append((method, args))
            if method == "db.hosts":
                self.n += 1
                if self.n == 1:
                    raise modern_error
                return {"hosts": [{"address": "10.0.0.5", "os_name": "Linux"}]}
            raise AssertionError(method)

    md = helpers.db_list_md(ModernDB(), "hosts")
    assert "10.0.0.5" in md and "Linux" in md
    assert calls == [("db.hosts", ()), ("db.hosts", ({},))]


def test_db_list_reports_unavailable_database():
    stub = _StubRPC({"db.hosts": MsfRPCError("database support has been disabled")})
    with pytest.raises(MsfRPCError) as exc:
        helpers.db_list_md(stub, "hosts")
    assert "database" in str(exc.value).lower()


def test_session_read_falls_back_to_modern_methods():
    class ModernSessions(_StubRPC):
        def call(self, method, *args, **_kwargs):
            self.calls.append((method, args))
            if method == "session.read":
                raise MsfRPCError("Unknown API Call: 'session.read'")
            if method == "session.shell_read":
                return {"seq": 0, "data": "uid=0(root)\n"}
            raise AssertionError(method)

    stub = ModernSessions()
    assert helpers.session_read(stub, "1") == "uid=0(root)\n"
    assert stub.calls[0][0] == "session.read"
    assert stub.calls[1][0] == "session.shell_read"


def test_session_read_honors_truncation():
    class Huge(_StubRPC):
        def call(self, *_a, **_kw):
            return {"data": "x" * 50_000}

    text = helpers.session_read(Huge(), "1")
    assert "chars truncated" in text


def test_session_write_adds_no_newline():
    stub = _StubRPC({"session.write": {"result": "success"}})
    helpers.session_write(stub, "2", "id")
    assert stub.calls == [("session.write", ("2", "id"))]


def test_console_run_creates_reads_and_destroys():
    reads = iter(
        [
            {"data": "", "busy": True, "prompt": ""},
            {"data": "[*] Metasploit v6", "busy": True, "prompt": ""},
            {"data": "\nmsf6 > ", "busy": False, "prompt": "msf6 > "},
            {"data": "", "busy": False, "prompt": "msf6 > "},  # flush read
        ]
    )
    calls: list[tuple] = []

    class ConsoleStub(_StubRPC):
        def call(self, method, *args, **_kwargs):
            calls.append((method, args))
            if method == "console.create":
                return {"id": "7", "prompt": "", "busy": False}
            if method == "console.write":
                assert args[1] == "version\n"  # helper appends the newline
                return {"wrote": 8}
            if method == "console.read":
                return next(reads)
            if method == "console.destroy":
                return {"result": "success"}
            raise AssertionError(method)

    output = helpers.console_run(ConsoleStub(), "version")
    assert "Metasploit v6" in output
    methods = [m for m, _ in calls]
    assert methods == [
        "console.create",
        "console.write",
        "console.read",
        "console.read",
        "console.read",
        "console.read",  # one extra read after the prompt to flush output
        "console.destroy",
    ]


def test_console_run_destroys_console_on_timeout_or_error():
    destroyed: list[str] = []

    class BusyStub(_StubRPC):
        def call(self, method, *args, **_kwargs):
            if method == "console.create":
                return {"id": "0"}
            if method == "console.read":
                return {"data": "", "busy": True, "prompt": ""}
            if method == "console.destroy":
                destroyed.append(args[0])
                return {"result": "success"}
            return {}

    out = helpers.console_run(BusyStub(), "sleep 999", timeout=0.5, poll_interval=0.05)
    assert "truncated" in out
    assert destroyed == ["0"]  # console always cleaned up


def test_execute_and_check_md():
    md = helpers.execute_md({"job_id": 0, "uuid": "abc-123"})
    assert "job_id" in md and "abc-123" in md
    cmd = helpers.check_md({"status": "completed", "result": "vulnerable"})
    assert "vulnerable" in cmd


# ---------------------------------------------------------------------------
# extra edge cases (deep-review round)
# ---------------------------------------------------------------------------


def test_sanitize_module_opts_handles_none_and_sanitizes_keys():
    assert sanitize_module_opts(None) == {}
    cleaned = sanitize_module_opts({"RH\nOSTS": "10.0.0.1\r\n", "\x00KEY": "v"})
    assert "\n" not in "".join(cleaned) and "\r" not in "".join(cleaned)
    assert cleaned == {"RH OSTS": "10.0.0.1 ", "KEY": "v"}


def test_search_modules_empty_query_keeps_order():
    raw = [{"fullname": "a"}, {"fullname": "b"}]
    assert helpers.search_modules(raw, "") == raw
    assert helpers.search_modules(raw, None) == raw  # type: ignore[arg-type]


def test_describe_options_empty_and_lowercase_modern_names():
    assert helpers.describe_options_md({}) == "*module has no options*"
    md = helpers.describe_options_md({"rhost": {"type": "address", "required": True}})
    assert "| Option |" in md and "rhost" in md


def test_module_info_md_empty_and_missing_rank():
    assert helpers.module_info_md({}) == ""
    md = helpers.module_info_md({"rank": "excellent", "name": "X"})
    assert "**Rank:** Excellent" in md


def test_validate_module_leading_slash_and_length():
    with pytest.raises(ValueError):
        helpers.validate_module("auxiliary", "/absolute/path")
    with pytest.raises(ValueError, match="too long"):
        helpers.validate_module("auxiliary", "a" * 250)


def test_session_write_validates_input():
    stub = _StubRPC()
    with pytest.raises(ValueError, match="non-empty"):
        helpers.session_write(stub, "1", "")
    with pytest.raises(ValueError, match="too long"):
        helpers.session_write(stub, "1", "x" * 9_000)
    assert stub.calls == []


def test_session_read_prefers_data_then_output_then_payload():
    class OutputKey(_StubRPC):
        def call(self, *_a, **_kw):
            return {"output": "legacy output text"}

    assert helpers.session_read(OutputKey(), "1") == "legacy output text"

    class NoKeys(_StubRPC):
        def call(self, *_a, **_kw):
            return {"other": {"nested": 1}}

    assert "nested" in helpers.session_read(NoKeys(), "1")


def test_console_run_validates_command_input():
    stub = _StubRPC()
    with pytest.raises(ValueError, match="must not be empty"):
        helpers.console_run(stub, "   ")
    with pytest.raises(ValueError, match="too long"):
        helpers.console_run(stub, "x" * 4_001)
    assert stub.calls == []


def test_console_run_raises_when_create_returns_no_id():
    stub = _StubRPC({"console.create": {"prompt": "", "busy": False}})
    with pytest.raises(MsfRPCError, match="no id"):
        helpers.console_run(stub, "version")


def test_console_run_accepts_numeric_console_id():
    calls: list[tuple] = []
    reads = iter(
        [
            {"data": "out", "busy": False, "prompt": "msf6 > "},
            {"data": "", "busy": False, "prompt": "msf6 > "},
        ]
    )

    class IntId(_StubRPC):
        def call(self, method, *args, **_kw):
            calls.append((method, args))
            if method == "console.create":
                return {"id": 3}  # modern daemon may return an int id
            if method == "console.read":
                return next(reads)
            return {"result": "success"}

    out = helpers.console_run(IntId(), "version", timeout=5)
    assert "out" in out
    assert ("console.write", ("3", "version\n")) in calls
    assert ("console.destroy", ("3",)) in calls


def test_db_list_unavailable_error_messages():
    no_db = MsfRPCError("No database connection defined.")

    class DownDB(_StubRPC):
        def call(self, *_a, **_kw):
            raise no_db

    with pytest.raises(MsfRPCError) as exc:
        helpers.db_list_md(DownDB(), "hosts")
    assert "database" in str(exc.value).lower() and "not loaded" in str(exc.value)

    class OddError(_StubRPC):
        def call(self, *_a, **_kw):
            raise MsfRPCError("weird transient failure")

    with pytest.raises(MsfRPCError, match="weird transient failure"):
        helpers.db_list_md(OddError(), "hosts")


# ---------------------------------------------------------------------------
# live smoke (opt-in; runs against a real msfrpcd when MSF_LIVE=1)
# ---------------------------------------------------------------------------


@msf_live
def test_live_version_and_search(recorded_rpc):  # noqa: ARG001
    import os

    rpc = from_env(
        {
            "MSF_RPC_PASS": os.environ.get("MSF_RPC_PASS", "scratchpass"),
            "MSF_RPC_HOST": os.environ.get("MSF_RPC_HOST", "127.0.0.1"),
            "MSF_RPC_PORT": os.environ.get("MSF_RPC_PORT", "55553"),
            "MSF_RPC_SSL": os.environ.get("MSF_RPC_SSL", "0"),
        }
    )
    with rpc:
        version = rpc.call("core.version")
        assert version["version"]
        results = rpc.call("module.search", "slowloris")
        fullnames = [m["fullname"] for m in results]
        assert "auxiliary/dos/http/slowloris" in fullnames
        info = rpc.call("module.info", "auxiliary", "dos/http/slowloris")
        assert "Slowloris" in info["name"]
        sessions = rpc.call("session.list")
        assert isinstance(sessions, dict)
