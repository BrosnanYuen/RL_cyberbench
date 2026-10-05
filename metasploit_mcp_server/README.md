# metasploit_mcp_server — Metasploit Framework MCP server (`metasploit`)

Stage 1B of the arena build (see `../PLAN.md` §2 "1B"). Lets LLM agents
(search, read, and — deliberately — run) Metasploit modules through MCP
tools, talking to a local `msfrpcd` over the msgpack RPC wire protocol.

Components:

| file | what |
|---|---|
| `metasploit_mcp/rpc.py` | hardened `MsfRPC` client: msgpack-over-HTTP transport, lazy login + token-refresh, newline sanitizer, `ensure_daemon()` |
| `metasploit_mcp/helpers.py` | validators (module names, ids, RHOSTS) + Markdown formatters (search/options/sessions/jobs/db/console) |
| `metasploit_mcp/server.py` | the MCP server (`msf_*` tools); installs `msf-mcp-server` |
| `server.py` | thin shim for `python server.py` / `mcp dev server.py` |
| `tests/` | mocked-transport unit tests + opt-in live tests (`MSF_LIVE=1`) |
| `tests/fixtures/recorded_rpc.json` | real msfrpcd response hashes used for record/replay |

## Install & run

```bash
pip install -e .            # into a venv (deps: mcp>=2.0, msgpack>=1.0)
msf-mcp-server              # stdio transport (installed entry point)
python server.py            # equivalent shim
uv run mcp dev server.py    # MCP Inspector
```

The server lives in the package namespace (`metasploit_mcp/server.py`); the
top-level `server.py` shim exists only for the commands above. The old
top-level module name collided with `pcap_to_md_mcp_server`'s `server` in a
shared venv (see `../BUGS.md`).

Needs a running `msfrpcd` (Metasploit Framework):

```bash
apt install metasploit-framework        # on Kali / agent container
msfrpcd -P "$MSF_RPC_PASS" -U msf -p 55553 -a 127.0.0.1 -f -n
```

Environment (read at first tool call; `MSF_RPC_PASS` is required):

```bash
MSF_RPC_HOST=127.0.0.1      MSF_RPC_PORT=55553
MSF_RPC_USER=msf            MSF_RPC_PASS=changeme   # required
MSF_RPC_SSL=1               # msfrpcd uses a self-signed cert by default
MSF_AUTOSTART=1             # spawn msfrpcd (loopback only) if nothing listens
```

With `MSF_AUTOSTART=1` the server starts `msfrpcd -P … -U … -p … -a 127.0.0.1 -f -n`
itself (no database — air-gapped lab) and waits for it to listen; msfrpcd
logs go to stderr (the container log).

## Tools

Read-only (`msf_check` is a health probe): `msf_check`, `msf_version`,
`msf_search_modules`, `msf_module_info`, `msf_module_options`,
`msf_session_list`, `msf_session_read`, `msf_job_list`, `msf_db_hosts`,
`msf_db_services`, `msf_db_vulns`, `msf_db_notes`, `msf_module_results`.

Action tools (annotated destructive — they **run code against the lab**):
`msf_module_execute` (module.execute with JSON datastore options),
`msf_module_check`, `msf_session_write`, `msf_session_stop`, `msf_job_stop`,
`msf_console_run` (ephemeral msfconsole; always destroyed afterwards).

Example flow:

```json
{"tool": "msf_search_modules", "args": {"query": "slowloris"}}
{"tool": "msf_module_info", "args": {"mtype": "auxiliary", "mname": "dos/http/slowloris"}}
{"tool": "msf_module_options", "args": {"mtype": "auxiliary", "mname": "dos/http/slowloris"}}
{"tool": "msf_module_execute",
 "args": {"mtype": "auxiliary", "mname": "dos/http/slowloris",
          "opts_json": "{\"rhost\": \"192.162.34.2\", \"rport\": 8080}"}}
{"tool": "msf_module_results", "args": {"uuid": "<uuid from execute>"}}
```

Module names: modern Metasploit frameworks use lower-case option names
(`rhost`/`rport`), older ones upper-case (`RHOSTS`/`RPORT`); both are
accepted by the tools — check `msf_module_options` for the exact keys.

### `.pi/mcp.json` (pi agent / Stage 2)

```json
{
  "mcpServers": {
    "metasploit": {
      "command": "/opt/mcp-venv/bin/msf-mcp-server",
      "env": { "MSF_RPC_PASS": "…", "MSF_AUTOSTART": "1" },
      "directTools": true,
      "toolPrefix": "none",
      "lifecycle": "lazy"
    }
  }
}
```

## Protocol & compatibility notes

Wire format: msgpack array over HTTP POST to `/api/` with
`Content-type: binary/message-pack`. Every call except `auth.login` carries
the session token as its first argument; tokens expire 300 s after last use
(`-t`), so the client re-logins automatically and retries once.

The client speaks **both** RPC generations transparently (unit-tested by
record/replay against a live-recorded Metasploit 6.5.0-dev session):

- legacy v1: HTTP 200 + `["success", payload]` / `["error", msg, …]`;
- modern v10: HTTP 200 + result maps, HTTP 4xx/5xx + `{"error": true, …}`.

Cross-version fallbacks are used where method names changed: session
read/write tries `session.read` → `session.shell_read` →
`session.ring_read` (resp. `session.write` → `session.shell_write` →
`session.meterpreter_write`), and `db.*` retries with `{}` when the modern
daemon requires an options hash.

## Security notes

- **Newline stripping (CVE-2026-5463 mitigation):** every string option
  value passed to `msf_module_execute`/`msf_module_check` is
  newline/CR/NUL-stripped *before* it is packed onto the wire
  (`sanitize_module_opts`). Newlines are *not* stripped from console/session
  writes (they are meaningful there) — those are length-capped instead.
- **Module references validated:** `mtype` must be a known module type and
  `mname` only `[a-zA-Z0-9_+./-]` (no `..`, no spaces/metacharacters); ids
  must be numeric; UUIDs must be hex/dash.
- **RHOSTS validated:** values for `rhost`/`rhosts` (any case) may only
  contain IP / CIDR / dash-range tokens — metacharacters (`;`, `|`, `$`,
  backticks, …) are rejected before the call.
- No `shell=True` anywhere; the daemon is spawned with argv only.
- The password is never logged or echoed in errors.
- HTTP transport: proxy env vars disabled; msfrpcd's self-signed cert is
  accepted (unverified) — loopback/internal traffic only.
- `MSF_AUTOSTART` refuses to spawn a daemon for non-loopback hosts.
- Console commands go through an ephemeral console that is **destroyed in
  a `finally` block** (even on timeout/error).

## Tests

```bash
make test PKG=metasploit_mcp_server      # unit: mocked msgpack/HTTP layer
MSF_LIVE=1 MSF_RPC_PASS=… MSF_RPC_SSL=0 pytest metasploit_mcp_server/tests -m msf_live
```

The `msf_live` tests run against a real `msfrpcd` (e.g. started with
`msfrpcd -P scratchpass -S -n -f`) and verify login, `core.version`,
`module.search slowloris` (must contain `auxiliary/dos/http/slowloris`) and
the full MCP tool stack over the wire.
