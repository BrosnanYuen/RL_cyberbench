# pcap_to_md_mcp_server — pcap/tcpdump → Markdown + MCP server (`pcap2md`)

Stage 1A of the arena build (see `../PLAN.md`). Converts packet captures into
Markdown an LLM can read:

| converter | output |
|---|---|
| **summary** | one `summary.md` — one line per packet (tshark Info column) |
| **full** | one `.md` **per packet** (protocol tree + hex dump) + `index.md` |
| **streams** | follow-stream conversations (`tcp/udp/tls/http/http2/quic`) as markdown; HTTP object export |
| **report** | `-z` statistics: protocol hierarchy, conversations, expert info |

All conversions are driven by a **single hardened `tshark` run** using
`-T json` (`-e …` for the summary table, `-x` for the full tree/hex):
the user hint "`tshark -T json` then convert to .md" is implemented literally.

## Install

```bash
pip install -e .            # into a venv
# system dependency:
sudo apt install tshark     # Wireshark CLI; text2pcap optional (fixtures)
```

## CLI

```bash
pcap2md summary capture.pcap -o summary.md
pcap2md full    capture.pcap -o packets/       # packets/packet_0001.md … + index.md
pcap2md report  capture.pcap -o report.md
pcap2md follow  capture.pcap --proto tcp --stream 0
# common flags: -Y 'http' (display filter), -c 5000 (max packets), --timeout
```

## MCP server

The server lives in the package namespace (`pcap_to_md/server.py`) and
installs the `pcap2md-server` console script. The top-level `server.py` is a
thin shim kept so `python server.py` / `uv run mcp dev server.py` still work
from this directory. (The old top-level module name collided with
`metasploit_mcp_server`'s `server` in a shared venv, so `pcap2md-server`
silently served the metasploit tools — see `../BUGS.md`.)

```bash
pcap2md-server                   # stdio transport (installed entry point)
python server.py                 # equivalent shim
uv run mcp dev server.py         # MCP Inspector
```

Tools (all read-only except the two that materialize `.md`/objects files,
annotated accordingly): `pcap_summary_md`, `pcap_full_md`,
`pcap_follow_stream_md`, `pcap_export_http_objects`, `pcap_report_md`,
`pcap_check` (tshark version probe).

### `.pi/mcp.json` (pi agent / Stage 2)

```json
{
  "mcpServers": {
    "pcap2md": {
      "command": "/opt/mcp-venv/bin/pcap2md-server",
      "directTools": true,
      "toolPrefix": "none",
      "lifecycle": "lazy"
    }
  }
}
```

`directTools` + `toolPrefix: none` make the agent see the bare
`pcap_summary_md` / `pcap_check` / … names (pi-mcp-adapter defaults to
namespace proxy tools with a `pcap2md_` prefix).

### Claude-style `mcpServers` config

```json
{
  "mcpServers": {
    "pcap2md": {
      "command": "/opt/mcp-venv/bin/pcap2md-server"
    }
  }
}
```

## Security notes

- Subprocesses via `asyncio.create_subprocess_exec` — **never** `shell=True`.
- Input paths allowlisted to `.pcap/.pcapng/.cap`, must exist, must be regular
  files; `..` traversal and null bytes rejected; symlink/stat checks applied.
- Output capped (head+tail truncation with an explicit marker, default 8000
  chars, hard cap 200 MB); every command has a wall-clock timeout (300 s
  default); packet-count caps on every converter.
- Hostile strings in display filters are passed as argv (inert — no shell
  interpolation) and covered by tests (`tests/test_tshark_runner.py`).

## Tests

```bash
pytest pcap_to_md_mcp_server/tests -q
```

Fixture `tests/fixtures/http.pcap` is generated from the committed hex dump
`tests/fixtures/http.hex` via `text2pcap` (regenerated automatically if
missing). Tests that need `tshark` are skipped with `pytest.mark.skipif` when
it is not installed.
