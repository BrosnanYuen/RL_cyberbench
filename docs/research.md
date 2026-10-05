# Research notes — Stages 1A/1C/1D (distilled)

Sources were surveyed in Sept 2026 during plan assembly; facts below are what
the implemented stages build against. (Full link list lands here as research
continues into Stages 2–4.)

## tshark JSON output (`-T json` / `-T ek`)

- `tshark -r f.pcap -T json` → one big JSON array; each packet is
  `{"_index": …, "_score": null, "_source": {"layers": {"frame": {…},
  "eth": {…}, "ip": {…}, …}}}`. Each protocol nests under its own key with
  dotted field names as keys.
- Adding `-e <field>` fields **suppresses** the full layer tree: the output
  contains only the requested fields, each as an array. This is why
  `summary.py` runs `-T json -e …` (small) and `full.py` runs `-T json`
  (tree) — the two shapes cannot be combined in one run, so full mode makes
  a second cheap `-e` pass for the `_ws.col.info` column.
- The Info/Protocol columns (`_ws.col.info`, `_ws.col.protocol`) are present
  only via `-e` fields. Without them the full tree has no Info column.
- `-T ek` emits one JSON object per line (`{"index": …}` then per packet
  `{"timestamp": …, "layers": …}`) — streamable, suited to huge captures.
- `-x` adds `<layer>_raw` siblings: `[hex_string, offset, size, …]`;
  `frame_raw[0]` is the full frame hex.
- `-T pdml` is the XML alternative with `showname` attributes per field.

## Statistics (`-z`)

- `-z io,phs` protocol hierarchy, `-z conv,ip` / `-z conv,tcp` conversations,
  `-z expert` expert info. Blocks are delimited by `====` rule lines;
  **expert output puts the rule after the section title** (`Errors (1)`,
  `Warns (1)`, `Notes (1)`, `Chats (1)` …), io,phs/conversations put a
  leading rule before each title. Output order of multiple `-z` flags varies
  by version → each report is requested in its own tshark run.
- `capinfos -c -u` → `Number of packets:` and `Capture duration:` (colon
  separated, not `=`).

## Follow streams

- `tshark -q -r f.pcap -z follow,<proto>,ascii,<idx>` for proto ∈
  {tcp, udp, tls, http, http2, quic}.
- tshark ≥ 4.x ascii output: per-chunk **length lines** (optionally
  tab-prefixed = Node 1 direction) whose value is the exact byte count of the
  following data; the classic `---` separator format appears in older
  releases. Both are parsed.
- HTTP objects: `tshark -r f.pcap --export-objects http,<dir>`. Objects are
  only emitted when the response is fully reassembled — a capture whose
  connection never FINs yields nothing.

## Security posture for subprocess use

- Always `asyncio.create_subprocess_exec` (argv list); never `shell=True` —
  display-filter metacharacters (`|`, `;`, `$( )`) are inert as argv.
- Path validation: extension allowlist `.pcap/.pcapng/.cap`, reject `..`,
  null bytes, directories, FIFOs; resolve symlinks.
- Output caps with head+tail truncation marker; wall-clock timeouts;
  packet-count caps via `-c`.
- MCP tools annotate read-only vs file-writing; invalid paths surface as
  `ToolError` → `is_error` tool results.

## python `mcp` SDK v2 (2.2.0)

- `from mcp.server.mcpserver import MCPServer` — `FastMCP` was renamed in v2.
- `@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))`; docstring →
  tool description; `Annotated[T, "doc"]` for parameter descriptions.
- Errors: `from mcp.server.mcpserver.exceptions import ToolError` → surfaces
  as `is_error` results.
- Testing: `async with mcp.Client(server) as client` (in-memory transport);
  `client.list_tools()` → `ListToolsResult.tools`; `client.call_tool(name,
  args)` → `CallToolResult(content, is_error)`.

## nmap (Stage 1C)

Sources: https://nmap.org/book/nse.html · https://nmap.org/nsedoc/categories/vuln.html

- Vulnerability scripts: `--script vuln`; boolean expressions supported
  (`--script "vuln and not dos"`, `--script "auth or brute"`, globs
  `http-vuln*`).
- NSE categories: `safe`, `version`, `auth`, `vuln`, `intrusive`, `brute`,
  `exploit`, `dos`, `discovery`, `default`. `dos`/`exploit` can crash or hang
  targets — deliberately excluded from the default wrapper expression.
- `-sV` version detection works unprivileged; `-sS` SYN scan and `-O` OS
  fingerprinting need root (or `CAP_NET_RAW`); unprivileged runs fall back to
  `-sT` connect scans silently. Docker's default capability set includes
  `NET_RAW`, so raw scans work in root containers.
- Service checks without the DoS: `--script http-slowloris-check` performs a
  susceptibility check, not the attack itself.
- Output: `-oA <prefix>` writes `.nmap` (text), `.gnmap` (grepable) and
  `.xml`; `-oG -` pipes grepable output to stdout (`Host: <ip> (<name>)
  Status: Up` — how `nmap_recon.sh` extracts live hosts).
- XML: `-oX` structure is `nmaprun > host > (address|hostnames|ports|os|hostscript)`,
  `port > (state|service|script)`; script results live in the `output`
  attribute with newlines encoded as `&#10;` (decoded by any XML parser).
  `xml.etree` (stdlib) is sufficient to parse it; parses are only done on
  files our own nmap runs produced.

## capture tooling (Stage 1D)

Sources: https://www.wireshark.org/docs/man-pages/ · https://tcpdump.org/manpages/

- Capture: `tcpdump -i <iface> -w out.pcap -s 0` (full packets) or
  `tshark -i <iface> -w out.pcap`; both need root/`CAP_NET_RAW` on the
  capture interface (agent containers run root + NET_ADMIN/NET_RAW).
- Bounded captures: wrap tcpdump with `timeout -s INT <secs>` (SIGINT makes
  tcpdump flush + print capture stats), or use tshark's `-a duration:<secs>`
  autostop. Ring buffers: tcpdump `-C 10 -W 5` (10 MB × 5 files).
- Filters: capture-time BPF (`-f`/trailing expression for tcpdump/tshark,
  always passed as a single argv element) vs display-time `-Y` — quick looks
  at finished pcaps: `tshark -r x.pcap -Y "http" -V`.
- `capinfos -c f.pcap` prints `File name:` first then
  `Number of packets:   <n>` (colon-separated, whitespace-padded) — parse the
  count from the `Number of packets` line, not the first number on screen
  (file paths may contain digits).
- Rotate/merge finished captures: `editcap -c 10000 in.pcap out.pcap`,
  `mergecap -w all.pcap pieces...`.
- Post-capture analysis flows through the Stage-1A pcap2md MCP tools
  (summary/full/follow-streams/report) — skills never re-implement dissection.

