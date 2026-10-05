"""Metasploit msgpack-RPC client (PLAN S1B.1).

Wire format (Metasploit RPC): a msgpack array over HTTP POST to
``/api/`` with ``Content-type: binary/message-pack``. Every call except
``auth.login`` carries the session token as its first argument. Tokens
expire (default 300 s after last use) so the client re-logins lazily on
the token-expired error and retries the call once.

Two server generations are supported transparently:

* legacy v1 (older metasploit):  HTTP 200 always; success ``["success", payload]``,
  error ``["error", message, ...]`` arrays.
* modern v10 (metasploit >= ~6.0): HTTP 200 with result maps
  (``{"result": "success", ...}``) and HTTP 4xx/5xx with
  ``{"error": true, "error_class": ..., "error_string": ...}`` maps.
  Some modern calls return bare payload maps/lists with HTTP 200.

Security hardening:

* the option sanitizer strips newlines / carriage returns / NUL from every
  string option value before it is sent (mitigates the CVE-2026-5463-style
  newline injection into msfrpcd);
* host values (``RHOSTS``/``rhosts``) are validated in :mod:`helpers`;
* the password is never echoed in errors or logs;
* HTTP transport disables proxy env vars and uses an unverified SSL context
  (msfrpcd's self-signed cert — lab-internal traffic only);
* ``ensure_daemon()`` only auto-starts msfrpcd bound to loopback.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

import msgpack

log = logging.getLogger("metasploit_mcp.rpc")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 55553
DEFAULT_USER = "msf"
DEFAULT_TIMEOUT = 30.0
DAEMON_BINARY = "msfrpcd"
DAEMON_START_TIMEOUT = 180.0
DAEMON_POLL_INTERVAL = 0.5

#: RPC methods that are valid without a token (auth.login is the bootstrap).
TOKENLESS_METHODS = frozenset({"auth.login"})

#: HTTP response code msfrpcd uses for token/auth failures.
HTTP_UNAUTHORIZED = 401


class MsfRPCError(RuntimeError):
    """A transport-level, protocol-level or remote RPC failure."""

    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class MsfRPCAuthError(MsfRPCError):
    """Login failed or credentials are wrong (no password is ever echoed)."""


class MsfRPCConfigError(MsfRPCError):
    """Client misconfiguration (missing env vars, bad port, non-loopback autostart)."""


class MsfRPCDaemonError(MsfRPCError):
    """msfrpcd is not reachable and could not be auto-started."""


class _TokenExpiredError(MsfRPCError):
    """Internal: the token expired and the caller should re-login and retry."""


def sanitize_option_value(value: Any) -> Any:
    """Strip newlines / carriage returns / NUL from string option values.

    Newline injection into msfrpcd option strings is the CVE-2026-5463
    vector; non-string values pass through untouched.
    """
    if isinstance(value, str):
        return (
            value.replace("\r\n", " ")
            .replace("\r", " ")
            .replace("\n", " ")
            .replace("\x00", "")
        )
    return value


def sanitize_module_opts(opts: dict[str, Any] | None) -> dict[str, Any]:
    """Return a new options dict with every string value newline-stripped."""
    return {
        sanitize_option_value(str(k)): sanitize_option_value(v)
        for k, v in (opts or {}).items()
    }


def _as_text(value: Any) -> Any:
    """Recursively decode msgpack ``bytes`` (server sends ASCII-8BIT strings
    as ``bin``) back into ``str`` so callers only ever see text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        return {_as_text(k): _as_text(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_as_text(v) for v in value]
    return value


def _short(value: Any, limit: int = 300) -> str:
    text = json.dumps(value, default=str, ensure_ascii=True)
    if len(text) <= limit:
        return text
    return text[:limit] + f"... ({len(text) - limit} chars truncated)"


def _is_token_error(text: str, code: int | None, authed: bool) -> bool:
    """Heuristic for "token missing/expired" across msfrpcd generations."""
    return "invalid authentication token" in text.lower() or bool(
        authed and code == HTTP_UNAUTHORIZED
    )


def _flatten_error_text(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("error_message", "error_string", "error_class"):
            if data.get(key):
                return str(data[key])
        return _short(data, 300)
    if isinstance(data, list) and data:
        return str(data[1]) if len(data) > 1 else str(data[0])
    return str(data)


class MsfRPC:
    """Thread-safe msgpack-RPC client for ``msfrpcd`` with lazy re-login.

    Usage::

        with MsfRPC(password="...", ssl_enabled=True) as rpc:
            version = rpc.call("core.version")
    """

    def __init__(
        self,
        password: str,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        user: str = DEFAULT_USER,
        ssl_enabled: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not password:
            raise MsfRPCConfigError("msfrpcd password is empty (MSF_RPC_PASS?)")
        if not str(port).isdigit():
            raise MsfRPCConfigError(f"invalid msfrpcd port: {port!r}")
        self.password = password
        self.host = host
        self.port = int(port)
        self.user = user
        self.ssl_enabled = ssl_enabled
        self.timeout = timeout
        self._token: str | None = None
        self._lock = threading.RLock()

    # -- lifecycle ---------------------------------------------------------

    @property
    def authenticated(self) -> bool:
        return self._token is not None

    @property
    def url(self) -> str:
        scheme = "https" if self.ssl_enabled else "http"
        return f"{scheme}://{self.host}:{self.port}/api/"

    def __enter__(self) -> MsfRPC:
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.logout()

    def login(self) -> str:
        """Authenticate and cache the session token (idempotent re-login)."""
        with self._lock:
            if self._token:
                return self._token
            resp = self._invoke("auth.login", (self.user, self.password), authed=False)
            token: str | None = None
            if isinstance(resp, dict):
                token = resp.get("token")
            elif isinstance(resp, str):
                token = resp  # legacy: ["success", "<token>"]
            if not token:
                raise MsfRPCAuthError(
                    f"unexpected auth.login response: {_short(resp, 120)}"
                )
            self._token = token
            return token

    def logout(self) -> None:
        """Best-effort token revocation; never raises."""
        with self._lock:
            if not self._token:
                return
            try:
                # msfrpcd expects the token both for auth and as the arg
                self._invoke("auth.logout", (self._token,), authed=True)
            except MsfRPCError:
                log.debug("auth.logout failed (ignored)")
            finally:
                self._token = None

    # -- core call path -----------------------------------------------------

    def call(self, method: str, *args: Any, timeout: float | None = None) -> Any:
        """Invoke an RPC method, re-logging-in once when the token expired."""
        authed = method not in TOKENLESS_METHODS
        with self._lock:
            if authed and self._token is None:
                self.login()
            try:
                return self._invoke(method, args, authed=authed, timeout=timeout)
            except _TokenExpiredError as e:
                log.warning("token expired for %s (%s); re-login and retry", method, e)
                if authed:
                    self._token = None
                    self.login()
                    return self._invoke(method, args, authed=True, timeout=timeout)
                raise MsfRPCAuthError(str(e)) from e

    def _invoke(
        self,
        method: str,
        args: tuple[Any, ...],
        *,
        authed: bool,
        timeout: float | None = None,
    ) -> Any:
        payload: list[Any] = [method]
        if authed:
            if not self._token:
                raise MsfRPCError("not authenticated — call login() first")
            payload.append(self._token)
        payload.extend(args)
        code, body = self._transact(
            msgpack.packb(payload), timeout=self.timeout if timeout is None else timeout
        )
        return self._decode(code, body, method=method, authed=authed)

    # -- transport (overridden in tests for record/replay) -------------------

    def _transact(
        self, payload: bytes, timeout: float | None = None
    ) -> tuple[int, bytes]:
        """POST *payload* to msfrpcd; return (http_status, body)."""
        request = urllib.request.Request(
            self.url,
            data=payload,
            method="POST",
            headers={"Content-type": "binary/message-pack"},
        )
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.ProxyHandler({})  # never honor proxy env for lab RPC
        ]
        if self.ssl_enabled:
            # msfrpcd ships a self-signed cert; the lab is air-gapped, and the
            # only secret in flight is the RPC token (fine over loopback).
            handlers.append(
                urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
            )
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(
                request, timeout=self.timeout if timeout is None else timeout
            ) as resp:
                return int(resp.status), resp.read()
        except urllib.error.HTTPError as e:
            return int(e.code), e.read()
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            raise MsfRPCDaemonError(
                f"msfrpcd unreachable at {self.url} ({reason}) — install/start "
                f"msfrpcd or set MSF_AUTOSTART=1"
            ) from e
        except TimeoutError as e:
            raise MsfRPCError(f"msfrpcd request timed out at {self.url}") from e

    # -- response decoding (both RPC generations) ----------------------------

    def _decode(self, code: int, body: bytes, *, method: str, authed: bool) -> Any:
        try:
            data = _as_text(msgpack.unpackb(body, raw=True, strict_map_key=False))
        except Exception as e:  # msgpack.exceptions.*, ValueError...
            text = body[:300].decode("utf-8", "replace")
            if code >= 400:
                raise self._mk_error(
                    code, text or f"HTTP {code}", authed, method
                ) from e
            raise MsfRPCError(f"invalid msgpack response from {self.url}: {e}") from e

        if isinstance(data, dict):
            if data.get("error") is True:
                raise self._mk_error(
                    code,
                    _flatten_error_text(data) or f"RPC error (HTTP {code})",
                    authed,
                    method,
                    detail=_short(data, 400),
                )
            if data.get("result") == "success":
                return {k: v for k, v in data.items() if k != "result"}
            return data

        if isinstance(data, list):
            if not data:
                return None
            head = str(data[0])
            if head == "success":
                return data[1] if len(data) > 1 else None
            if head == "error":
                message = str(data[1]) if len(data) > 1 else "RPC error"
                raise self._mk_error(
                    code, message, authed, method, detail=_short(data, 400)
                )
            return data  # e.g. module.search result list

        return data

    def _mk_error(
        self,
        code: int,
        message: str,
        authed: bool,
        method: str,
        *,
        detail: str | None = None,
    ) -> MsfRPCError:
        text = f"{message} {detail or ''}".strip()
        if _is_token_error(text, code, authed) and method != "auth.login":
            return _TokenExpiredError(f"authentication token rejected (HTTP {code})")
        if method == "auth.login":
            # never leak whether user or password was wrong
            return MsfRPCAuthError(
                f"auth.login failed at {self.url} — check MSF_RPC_USER/MSF_RPC_PASS "
                f"(HTTP {code})"
            )
        return MsfRPCError(f"metasploit {method} failed: {message}", code=code)


# ---------------------------------------------------------------------------
# daemon management
# ---------------------------------------------------------------------------


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if something listens on host:port."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_daemon(
    *,
    password: str,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    user: str = DEFAULT_USER,
    ssl_enabled: bool = True,
    start_timeout: float = DAEMON_START_TIMEOUT,
    poll_interval: float = DAEMON_POLL_INTERVAL,
) -> None:
    """Start ``msfrpcd`` if nothing answers on host:port yet.

    Auto-start is only allowed on loopback (the agent container's own
    msfrpcd); remote daemons must be managed out-of-band. The spawned
    process logs to stderr so it shows up in the container's logs.
    """
    if port_open(host, port):
        return
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise MsfRPCDaemonError(
            f"msfrpcd not reachable at {host}:{port} and MSF_AUTOSTART only "
            f"works for loopback hosts"
        )
    binary = shutil.which(DAEMON_BINARY)
    if binary is None:
        raise MsfRPCDaemonError(
            f"msfrpcd not reachable at {host}:{port} and '{DAEMON_BINARY}' is not "
            f"on PATH — apt install metasploit-framework"
        )
    cmd = [
        binary,
        "-P",
        password,
        "-U",
        user,
        "-p",
        str(port),
        "-a",
        host,
        "-n",  # no database (air-gapped lab)
        "-f",  # foreground; stderr stays attached for container logs
    ]
    if not ssl_enabled:
        cmd.append("-S")
    log.info("starting msfrpcd: %s", " ".join(_redact_password(cmd)))
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=None,
        start_new_session=True,
    )
    deadline = time.monotonic() + start_timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise MsfRPCDaemonError(
                f"msfrpcd exited during startup (code {proc.returncode}); "
                f"check container logs"
            )
        if port_open(host, port):
            log.info("msfrpcd is up on %s:%s", host, port)
            return
        time.sleep(poll_interval)
    raise MsfRPCDaemonError(
        f"msfrpcd did not listen on {host}:{port} within {start_timeout:.0f}s "
        f"(first startup loads all modules; see container logs)"
    )


# ---------------------------------------------------------------------------
# env-var configuration (server.py)
# ---------------------------------------------------------------------------


def env_flag(value: str | None, default: bool = False) -> bool:
    """Parse ``1/true/yes/on`` (case-insensitive) as True."""
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _redact_password(argv: list[str]) -> list[str]:
    """Mask the ``-P <password>`` argument for logs/errors."""
    out: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            out.append("***")
            redact_next = False
        elif arg == "-P":
            out.append(arg)
            redact_next = True
        else:
            out.append(arg)
    return out


def from_env(env: Mapping[str, str] | None = None) -> MsfRPC:
    """Build a client from ``MSF_RPC_HOST/PORT/USER/PASS/SSL/AUTOSTART``.

    ``MSF_RPC_PASS`` is required; with ``MSF_AUTOSTART=1`` a local
    ``msfrpcd`` is started if nothing is listening yet.
    """
    env = os.environ if env is None else env
    password = env.get("MSF_RPC_PASS", "")
    host = env.get("MSF_RPC_HOST", DEFAULT_HOST)
    user = env.get("MSF_RPC_USER", DEFAULT_USER)
    try:
        port = int(env.get("MSF_RPC_PORT", str(DEFAULT_PORT)))
    except ValueError as e:
        raise MsfRPCConfigError(
            f"MSF_RPC_PORT is not an integer: {env.get('MSF_RPC_PORT')!r}"
        ) from e
    raw_timeout = env.get("MSF_RPC_TIMEOUT", str(DEFAULT_TIMEOUT))
    try:
        timeout = float(raw_timeout)
    except ValueError as e:
        raise MsfRPCConfigError(
            f"MSF_RPC_TIMEOUT is not a number: {raw_timeout!r}"
        ) from e
    if timeout <= 0:
        raise MsfRPCConfigError(f"MSF_RPC_TIMEOUT must be positive: {raw_timeout!r}")
    client = MsfRPC(
        password=password,
        host=host,
        port=port,
        user=user,
        ssl_enabled=env_flag(env.get("MSF_RPC_SSL"), default=True),
        timeout=timeout,
    )
    if env_flag(env.get("MSF_AUTOSTART")):
        ensure_daemon(
            password=password,
            host=host,
            port=port,
            user=user,
            ssl_enabled=client.ssl_enabled,
        )
    return client
