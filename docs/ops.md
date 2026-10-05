# ops.md — Stage 2/3 runbook (this machine)

## Environment

| What | Value |
|---|---|
| Host | EndeavourOS (Arch), no passwordless sudo |
| Docker | 29.7.2, CDI GPU runtime (`nvidia.com/gpu=0/1/all`) |
| GPUs | RTX 3090 24GB + RTX 5070 Ti 16GB (pooled 40GB) |
| containerlab | 0.79.0 via dockerized wrapper (`llm_pentest_network/clab.sh`) |
| Model | `Huihui-Qwen3.8-27B-abliterated-UD-DW-Q4_K_M.gguf` (15.4 GiB) |
| Inference | llama.cpp `llama-server` built inside `pentestlab/llama-server` (CUDA 13.3, sm_86 + sm_120) |

## One-time host fixes

```bash
# GPU CDI spec was stale (libnvidia-egl-wayland missing) — regenerate:
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
# containerlab: no root -> dockerized wrapper is used automatically by clab.sh
```

## Build

```bash
make images        # webserv innoclient fw-logger fw-coraza orchestrator agent-kali llama-server
# agent-kali needs the Stage-1 packages; llama-server copies ./llama.cpp into
# the build context (source only, .git/build excluded).
make image-fw-coraza   # only the Coraza firewall image (Go + embedded CRS build)
```

## Deploy / run

```bash
make lab-up        # round 0: mgmt network, volumes, model seeding, clab deploy
make lab-down      # clab destroy + rm llm-atk/llm-def
make ui            # http://127.0.0.1:8088 (binds 127.0.0.1 only)
```

`run_lab.py` flags: `--mode inference|rl`, `--rounds N`, `--resume N`,
`--seed N`, `--attack-budget/--defend-budget` (phase wall-clocks),
`--deploy-only`, `--scripted` (no-GPU smoke test), `--event-log PATH`,
`--firewall-engine bunkerweb|coraza`.

### Firewall engines (interchangeable)

`configs/lab.default.yaml` -> `firewall.engine` selects the stack; both expose
the same lab contract, so defender protocol / judge / fw-logger / UI work
unchanged:

| | `bunkerweb` (default) | `coraza` |
|---|---|---|
| nodes | `fw` + `fw-sched` + `fw-redis` + `fw-api` | `fw` (`pentestlab/fw-coraza`) |
| WAF | ModSecurity + CRS (nginx) | OWASP Coraza v3 + embedded CRS 4.25 |
| settings | scheduler env, recreated on Phase-3 apply | `/etc/fw/runtime.env` + `POST /reload` |
| custom rules | `defense_changes/bunkerweb_custom_confs/*.conf` | `defense_changes/firewall_custom_rules/*.conf` (SecLang) |
| admin API | `:5000` `Host: bwapi` | `:5000` (same endpoints) |
| audit source | `modsec_audit.log` | `/var/log/coraza/audit.jsonl` |

```bash
make image-fw-coraza                                  # build the coraza image first
.venv/bin/python llm_pentest_network/run_lab.py --deploy-only --firewall-engine coraza
make collect FIREWALL=coraza                          # collection run on coraza
# or set `firewall.engine: coraza` in configs/lab.default.yaml
```

Shared defense settings file/keys (both engines): `bunkerweb_settings.env`
with `USE_MODSECURITY` (WAF on/off). Coraza additionally accepts `WAF_VARIANT`
(`global|path`), `WHITELIST_IP`, `BLACKLIST_IP`; anything else is rejected with
`defense_rejected_key`. `--fresh` wipes both engines' state volumes.

### Inference model profiles

`configs/lab.default.yaml` selects `inference.profile` (profiles are defined
in `llm_pentest_network/lab/config.py`; explicit `inference.<key>` values
override profile defaults):

| Profile | Files in `models/` | Spec-decode |
|---|---|---|
| `qwen3.8-27b-mtp` (default) | `Huihui-Qwen3.8-27B-abliterated-UD-DW-Q4_K_M.gguf` | built-in NextN head: `--spec-type draft-mtp --spec-draft-n-max 3` |
| `muse-glimmer-30b-dflash` | `Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf` + `dflash-Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf` | DFlash: `-md /models/draft.gguf --spec-type draft-dflash --spec-draft-n-max 15 -ngld 999 --jinja` |

```bash
# download the Muse pair (~18.5 GB; hf CLI in ~/.local/bin)
hf download Blackfrost-AI/Muse-Glimmer-30B-Abliterated-GGUF \
    Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf \
    dflash-Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf --local-dir models/
# switch: configs/lab.default.yaml -> inference.profile: muse-glimmer-30b-dflash
make lab-up     # deployer re-seeds model-attacker/model-defender automatically
```

DFlash needs llama.cpp ≥ b10353; the vendored source is b10869 (already has
`draft-dflash`, `-md`, `-ngld`) and DFlash runs under `llama-server` only.
The deployer stamps `model.gguf`/`draft.gguf` with a `.<name>.src` marker and
falls back to a byte-size check, so profile switches re-seed without wiping
volumes while Stage-4 promoted weights stay in place as long as the profile
is unchanged. `sync_llm_endpoint` rewrites pi's `models.json` model id to the
profile's `model_id` (llama-server `--alias`).

## Stage 3 (25-round inference collection)

```bash
make collect                       # full run; logs to qwen_dataset/datasets/events.jsonl
make collect-resume ROUND=7        # after a crash/interrupt
make validate                      # S3.5 acceptance gate
```

### Collection variants (separate datasets)

Each attacker thinking level / attack strategy writes its own dataset dir
(provenance in `_collection.json`):

```bash
make collect-low-thinking          # qwen_dataset/dataset_low_thinking/  (--thinking low)
make collect-medium                # qwen_dataset/dataset_medium/        (--thinking medium)
make collect-xhigh                 # qwen_dataset/dataset_xhigh/         (--thinking xhigh)
make collect-metasploit            # qwen_dataset/dataset_metasploit/    (--attack-strategy metasploit)
make collect-scapy                 # qwen_dataset/dataset_scapy/         (--attack-strategy scapy)
make collect DATASET=ds THINKING=high STRATEGY=scapy   # generic
make validate DATASET=qwen_dataset/dataset_xhigh
make collect-resume ROUND=7 DATASET=qwen_dataset/dataset_xhigh THINKING=xhigh
```

Muse-Glimmer-30B (DFlash) uses the same variant matrix under `muse_dataset/`
and forces `--profile muse-glimmer-30b-dflash`:

```bash
make collect-muse-all              # every muse variant, sequentially (long run)
make collect-muse                  # muse_dataset/datasets/
make collect-muse-low-thinking     # muse_dataset/dataset_low_thinking/  (--thinking low)
make collect-muse-medium           # muse_dataset/dataset_medium/
make collect-muse-xhigh            # muse_dataset/dataset_xhigh/
make collect-muse-metasploit       # muse_dataset/dataset_metasploit/
make collect-muse-scapy            # muse_dataset/dataset_scapy/
make collect-muse-nuclei           # muse_dataset/dataset_nuclei/
make collect-muse-zap              # muse_dataset/dataset_zap/
```

`--thinking` maps to pi's `--thinking off|minimal|low|medium|high|xhigh|max`
(attacker only); `--attack-strategy` appends a Metasploit- or scapy-focused
directive to the attacker prompt. The defender phase is identical in all
variants.

All variant targets pass `--fresh`: the running lab is destroyed and the
stateful volumes are wiped (`attacker_ws`, `defender_ws`, `customconfs`,
`bw-data`, `webserv_patch`, `client_patch`, `fwlogs`, `fwstate`,
`fwlog-bunkerweb`, `coraza_rules`, `fwlog-coraza`) before round 0, and the
dataset + captures dirs are cleared — so each dataset starts with no prior
agent memory or firewall state. Model volumes are kept. Pcaps are written to
`<dataset>/captures/`.

- Schedule: P0–P3 each round (stage3_mode=true).
- Artifacts: `qwen_dataset/datasets/round_XX/phase_{1,3}/{attacker,defender}_transcript.jsonl`,
  `score.json`, `episode.json`; pcaps in `captures/`; `firewallog.json` copied
  by phase runner.
- Dashboard: `qwen_dataset/datasets/_dashboard.json` + Web UI scores panel.

## Architecture decisions & workarounds

1. **containerlab without root**: `clab.sh` runs `ghcr.io/srl-labs/clab` in a
   privileged helper container (docker.sock + host PID namespace), the
   officially supported pattern. `/etc/hosts` entries land in the ephemeral
   helper (harmless). All node wiring is standard clab p2p links.
2. **GPU in clab**: clab passes `devices:` to HostConfig.Devices as raw paths
   (no CDI resolution via API) → llama-server sidecars are created with
   `docker run --gpus all` (CLI resolves CDI) and adopted as
   `kind: ext-container` nodes (node name == container name). Their link IPs
   are assigned by the orchestrator (`assign_llm_ips`) since ext-containers
   don't run clab `exec`.
3. **llama.cpp**: host glibc is too new to copy binaries → built inside the
   image from the repo-local source (CUDA archs 86;120, build b10869). q8_0 KV
   cache, ctx 131072 fits the 40GB pool (weights 15.4GB + KV ≈ 18GB); only ONE
   sidecar is active per phase (P1 attacker, P3 defender). Speculative decoding
   is profile-driven: `qwen3.8-27b-mtp` uses the GGUF's built-in NextN head
   (`--spec-type draft-mtp`, `qwen35.nextn_predict_layers=1`): measured
   44 → 75-86 t/s (~63% draft acceptance) at +~1.5GB VRAM;
   `muse-glimmer-30b-dflash` adds Blackfrost's DFlash drafter (`-md`, block
   diffusion). Disable with `inference.spec_type: none` in
   `configs/lab.default.yaml`.
4. **Named volumes** in clab go into the `volumes:` stanza (NOT `binds:`).
5. **Firewall engines**: `bunkerweb` settings live on the scheduler env and
   defense changes recreate `fw-sched` with merged env (no data links → safe);
   internal API `http://<fw>:5000` with `Host: bwapi`. `coraza` is a single Go
   container WITH data links, so defense changes are applied at runtime
   (`/etc/fw/runtime.env` + `POST /reload`, bans via `/ban`) and custom
   SecLang rules are validated during reload (invalid rules keep the previous
   WAF active and fail the apply).
6. **Innocent clients** run `sleep infinity` as PID 1; the orchestrator starts
   the client binary via exec so restarts don't kill the container.

## Troubleshooting

- `clab deploy` fails "Failed to verify bind path" → binds must be host
  paths; named volumes belong in `volumes:`.
- llama-server container restart-loops → check `docker logs llm-atk`; OOM =
  lower `inference.ctx_size` in `configs/lab.default.yaml`.
- Agents can't reach the LLM → verify `assign_llm_ips` ran (eth1 has an IP)
  and `pi models.json` baseUrl matches the llm sidecar link IP (entrypoint
  gets `LLM_HOST` env at deploy time).
- `docker build` "file not found in build context" → build with absolute
  paths / from inside the image dir (legacy builder quirk with deep relative
  contexts).
- Coraza fw returns 502 → backend unreachable; check `docker logs clab-...-fw`
  (verified via `docker exec clab-...-fw curl http://<web_ip>:8080/healthz`).
- Coraza WAF does not block → seeded vuln (WAF off) is expected at first;
  enable with `POST /reload` or the defense settings file, then check
  `/var/log/coraza/audit.jsonl`.
- Coraza custom rule rejected → `POST /reload` returns 400 with the SecLang
  error; the previous rule set stays active (nothing to roll back).

## Stage 3 runbook (25-round collection, this machine)

```bash
# production run (launched via setsid; logs to /tmp/opencode/stage3.log):
.venv/bin/python llm_pentest_network/run_lab.py --mode inference --rounds 25 \
    --event-log qwen_dataset/datasets/events.jsonl
# resume after an interruption:
.venv/bin/python llm_pentest_network/run_lab.py --mode inference --rounds 25 --resume N
make validate
```

Per-round wall clock ≈ 35–75 min (P0 ~2 min + P1 ≤ 30 min + P2 ~2 min + P3 ≤ 40 min,
27B Q4_K_M at ~35 tok/s on the pooled GPUs). Expected total: 15–30 h.

## Emergent behaviors observed in validation (round 0)

- The attacker agent read `/targets/firewall/lab-src/judge.py`, understood the
  deterministic watchdog probe, and **banned 127.0.0.1 on the firewall via the
  admin API** so the local health probe would 403 → fake "crash" event (+5).
  This is a legitimate find: the internal API's attack surface is part of the
  game (defenders should restrict it). The agent-mgmt lockdown (iptables on
  eth0, applied at deploy) confines agents to their data links + LLM sidecar.
- The attacker stole the real secret via the backend but did not write
  `/workspace/loot/secret.json` → the +10 row did not fire (protocol
  violations are the RL signal — the manifest/loot protocol is normative).

## Fixes from round-0 transcript analysis (2026-09-09, see BUGS.md)

> Historical first pass. The sidecar/mgmt details below were superseded by the
> per-role private LLM networks and the second-pass fixes above; kept for the
> record.

- **Mgmt isolation is intended** (defense-in-depth): attacker eth0 OUTPUT
  allows ONLY the LLM sidecar + 172.31.0.1, everything else DROP. The
  attacker's ban-via-internal-API route over mgmt is dead by design; the
  attacker prompt/SYSTEM.md say so explicitly. The defender's ban path uses
  the firewall's data-plane IP (defender eth1 ↔ fw eth7).
- **MCP tool wiring fixed**: the agent image now installs `pi-mcp-adapter`
  (the component that reads `.pi/mcp.json`) and the orchestrator runs
  `pi --mode rpc` with cwd `/workspace` so the project MCP config is
  discovered. Both agents see `pcap2md` + `metasploit` tools.
- **Agent toolkit extended**: `ping` (`iputils-ping`), `scapy`
  (`python3-scapy` + venv), arp-scan, traceroute, nc, socat, macchanger,
  nikto, sqlmap, hydra, sslscan, whatweb. Stage 1E `scapy_skill/` documents
  the ARP `struct.error` trap and provides validated wrappers.
- **80% budget steer**: the orchestrator sends a role-specific
  "finalize artifacts NOW" steer at 80% of the phase wall-clock
  (`agent_budget_warning` event on the bus/UI).

## Stable LLM sidecar IPs (private per-role networks)

| node | network | subnet | IP |
|---|---|---|---|
| `llm-atk` | `pentestlab-llm-atk` | `172.30.0.0/24` | `172.30.0.200` |
| `llm-def` | `pentestlab-llm-def` | `172.29.0.0/24` | `172.29.0.201` |

Each agent is moved off `pentestlab-mgmt` onto its role's private bridge by
`harden_containers` (after every deploy/reconfigure); the sidecar is created
there by `_run_llm_container`. The agent's `~/.pi/agent/models.json` is
re-synced every phase (`sync_llm_endpoint` reads the sidecar IP from docker
inspect) and the eth0 OUTPUT lockdown allows only that sidecar.

## Stage-3 preflight fixes, second pass (2026-09-10, see BUGS.md)

- **pi/adapter versions pinned**: Node `22.23.2`, pi `0.85.1`,
  `pi-mcp-adapter@2.32.1`. The stale cached pi `0.74.2` could not load the
  adapter (`pi-ai/dist/index.js/compat` missing) and every phase scored an
  instant refusal. `make image-agent` now fails if the adapter is absent.
- **MCP direct tools**: `configs/pi/mcp.json` sets `directTools: true` and
  `toolPrefix: "none"` per server -> the schema exposes `pcap_check`,
  `pcap_summary_md`, ..., `msf_check`, `msf_search_modules`, ... (25 tools,
  verified with a tool-dump extension in both containers).
- **BunkerWeb volumes**: `sanitize_custom_configs` chowns `customconfs` and
  `bw-data` to `101:101` (bunkerweb images run as `scheduler`/`nginx`); fresh
  root-owned volumes otherwise crash-loop the scheduler with
  `PermissionError`. Defender confs are copied to `server-http/` (or a valid
  `<type>__<name>.conf` type) and invalid `bw_custom_configs` rows are purged.
- **fw health probe**: `wait_healthy` requires the proxied `/healthz` body
  (`ok`), not just HTTP 200 (the "Generating..." placeholder also returns 200).
- **Prompts** list the MCP tools (`pcap_*`, `msf_*`) as available; the model
  still prefers `bash` in practice (0 MCP calls in the audited traces).

## Tool availability (verified 2026-09-10, both roles)

- `kali-linux-headless 2026.3.4` (2262 executables); `ping` + `scapy 2.7.0`
  (system and `/opt/mcp-venv`) functional; 24 probed tools ran
  (nmap, msfconsole, sqlmap, hydra, nikto, ffuf, gobuster, hashcat, john,
  responder, mitmproxy, hping3, arp-scan, arping, macchanger, whatweb,
  sslscan, tshark, tcpdump, curl, wget, nc, socat, ping).
- MCP: `pcap_check` -> TShark 4.6.6; `msf_version` -> Metasploit 6.5.3-dev
  (msfrpcd autostart via `MSF_AUTOSTART=1`). The adapter-spawned msf server
  carries `MSF_RPC_PASS` from `.pi/mcp.json` (the container env has it too).
- Known non-issue: `go` is not installed (not a Kali tool); the defender's
  webserver patches are rebuilt by the orchestrator, not locally.
