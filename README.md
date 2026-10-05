# LLM Red-Team / Blue-Team Pentest RL Arena

Build plan: see `PLAN.md` (master) and `AGENT.md` (spec). Work proceeds in
stages; the repository currently implements:

## Stage 1A — `pcap_to_md_mcp_server/` (complete)

pcap/tcpdump → Markdown converters (`summary`, `full`, `streams`, `report`)
exposed both as the `pcap2md` CLI and as an MCP server for LLM agents.
See `pcap_to_md_mcp_server/README.md`.

## Stage 1B — `metasploit_mcp_server/` (complete)

Hardened Metasploit Framework RPC client (`MsfRPC`, msgpack over HTTP to
`msfrpcd`, lazy re-login, newline/RHOSTS sanitization) + MCP server with
`msf_*` tools (search/inspect/execute modules, sessions, jobs, console,
db listings). Works against both legacy and modern msfrpcd wire formats.
See `metasploit_mcp_server/README.md`.

## Stage 1C — `nmap_skill/` (complete)

Agent skill (`SKILL.md`) + wrappers (`nmap_vuln_scan.sh`, `nmap_recon.sh`) +
`parse_nmap_xml.py` (nmap XML → markdown digest) so agents can run and read
vulnerability scans. See `nmap_skill/README.md`.

## Stage 1D — `wireshark_skill/` (complete)

Agent skill (`SKILL.md`) + capture helpers (`capture.sh`, `quick_triage.sh`)
for collecting lab traffic with tcpdump/tshark and triaging pcaps. See
`wireshark_skill/README.md`.

## Stage 1E — `scapy_skill/` (complete)

Agent skill (`SKILL.md`) + scapy wrappers (`arp_scan.py` with per-host
fallback, `arp_spoof.py` with restore-on-exit, `ping_sweep.py`, `sniff.py`)
for raw-packet work: ARP sweeps/spoofing with correct MAC→bytes handling,
ICMP sweeps, bounded sniffing to pcap. See `scapy_skill/README.md`.

## Stage 1F — `nuclei_skill/` (complete)

Agent skill (`SKILL.md`) for ProjectDiscovery's **nuclei** template-driven
vulnerability scanner (ships in Kali). Wrappers (`nuclei_scan.sh`,
`nuclei_custom.sh`) are air-gap safe — always `-duc` (no template update
check) and `-ni` (no interactsh/OAST) — and turn findings into a
severity-grouped markdown digest (`parse_nuclei_jsonl.py`). The community
template library is baked into the agent image at build time
(`/opt/nuclei-templates`, pinned release; `NUCLEI_TEMPLATES_DIR`), since
nuclei auto-downloads templates on first run and the lab has no internet.
Agents can also write their own deterministic YAML templates (e.g. a
WAF-disabled SQLi probe). See `nuclei_skill/README.md`.

## Stage 1G — `zap_skill/` (complete)

Agent skill (`SKILL.md`) for **OWASP ZAP** (Kali's integrated web DAST, by
Checkmarx). Wrappers (`zap_quick_scan.sh`, `zap_plan_scan.sh`,
`zap_daemon.sh`) are air-gap safe — always `-silent` (no update checks) and
`-notel` (no telemetry) — and turn alert JSON into a risk-grouped markdown
digest (`parse_zap_alerts.py`). The skill's automation-plan cookbook lets
agents write their own YAML plans (`env` + `requestor`/`spider`/
`activeScan`/`report` jobs) for deterministic DAST checks of the lab's
exact bugs, and the daemon REST API guide covers incremental spider/ascan
drives via curl. See `zap_skill/README.md`.

## Stage 2 + 3 — `llm_pentest_network/` (implemented)

containerlab-based pentest arena: attacker/defender Kali agents (pi 0.85.1 +
pi-mcp-adapter 2.32.1 + `kali-linux-headless` incl. scapy/ping + skills +
the `pcap2md`/`metasploit` MCP servers, local llama.cpp inference on GPU),
**interchangeable firewall engines** (`firewall.engine: bunkerweb|coraza`:
BunkerWeb 1.6.14 stack or a single `pentestlab/fw-coraza` Go container with
OWASP Coraza v3 + embedded CRS 4.25 — same reverse proxy, admin API, defense
protocol and `firewallog.json` contract), Go webservers/innocent clients
(h1/h2c/h3), deterministic judge, transcript collection, Web UI. Agents run on
private per-role LLM bridges (no shared L2 with the lab mgmt network). Stage 3 =
25-round inference collection via `make collect`. See
`llm_pentest_network/README.md` and `docs/ops.md`; round-by-round bug
analyses and fixes live in `BUGS.md`.

## Stage 4 — `SFT_pentest_network/` (implemented; Colab/GPU runs pending)

Unsloth supervised fine-tuning of the attacker/defender Qwen3.8-27B policies
from the Stage 3B files: config-driven precision (`auto|fp8|4bit|16bit`; true
FP8 gated to sm89+ GPUs with ≥48 GB, bnb-4bit QLoRA otherwise), fp16-NaN-safe
training, no-warmup lr 4e-4, adapters /
merged-16bit / GGUF Q4_K_M exports (optional FP8 via `llm-compressor`) and
GGUF promotion into the arena model volumes. Colab notebook:
`SFT_pentest_network/colab/sft_qwen3_8_27b_colab.ipynb`. See
`SFT_pentest_network/README.md` and `PLAN.md` §6.

## Stage 5 — `RL_pentest_network/` (implemented; GPU/Colab runs pending)

Unsloth **GRPO** refinement of the two policies, starting from the Stage 4
SFT v3 adapters (`hf-user/Qwen3.8-27B-SFT-Attacker-v3` /
`...-Defender-v3`, r=64 LoRA on `unsloth/Qwen3.8-27B-unsloth-bnb-4bit`):
K on-policy rollouts per state (live arena or offline JSONL), each scored by
the deterministic `lab.judge` (AGENT.md tables) — no LLM reward model.
Config-driven schedule (alternating attacker/defender), PLAN §7 hyperparameters
(lr 1e-4 — AGENT.md says 4e-4; no warmup, trained≠initial, attacker≠defender
verification), exports (adapters / merged-16bit / GGUF Q4_K_M)
and promotion into the arena model volumes + `llm-atk`/`llm-def` sidecar
restart. `--mode rl` runs it via the lab runner; the Web UI training page
streams `rl.metrics` (loss/reward/kl/lr). Colab notebook:
`RL_pentest_network/colab/grpo_colab.ipynb` — **A100 80 GB, one policy
(attacker XOR defender) per session** via `configs/rl.colab.yaml` +
`rl.train`'s single-policy guard. See
`RL_pentest_network/README.md` and `PLAN.md` §7.

## Models (gitignored)

Inference model is selected by `inference.profile` in
`llm_pentest_network/configs/lab.default.yaml` (profiles live in
`llm_pentest_network/lab/config.py`); both profiles run on the same
llama.cpp `llama-server` sidecar.

- **`qwen3.8-27b-mtp` (default)** —
  `models/Huihui-Qwen3.8-27B-abliterated-UD-DW-Q4_K_M.gguf`, Q4_K_M GGUF of
  `huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF`, 15.4 GiB, downloaded
  2026-09-08. SHA-256 `0c7cfe3060493485bb9a6a51195897b0c1d347a49929206adb9a52170183ea03`
  verified against the HF repo LFS oid. Speculative decode uses the model's
  built-in NextN/MTP head (`--spec-type draft-mtp --spec-draft-n-max 3`).
- **`muse-glimmer-30b-dflash`** — `Blackfrost-AI/Muse-Glimmer-30B-Abliterated-GGUF`
  (2026-09-13): target `models/Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf`
  (16.9 GB) + DFlash drafter
  `models/dflash-Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf` (1.63 GB);
  `--spec-type draft-dflash --spec-draft-n-max 15 -ngld 999 --jinja`
  (llama.cpp ≥ b10353 required; vendored build is b10869). Download with
  `hf download Blackfrost-AI/Muse-Glimmer-30B-Abliterated-GGUF \
  Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf \
  dflash-Muse-Glimmer-30B-Abliterated-Q4_K_M.gguf --local-dir models/`.
- Seeded onto `model-attacker` / `model-defender` docker volumes by the
  deployer and served by the `llm-atk` / `llm-def` llama-server sidecars
  (llama.cpp built with CUDA sm_86/sm_120, q8_0 KV cache, ctx 131072).
  Switching profile re-seeds the volumes automatically.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -e 'pcap_to_md_mcp_server[dev]' \
  -e 'metasploit_mcp_server[dev]' pyyaml pytest ruff mypy
make test                                   # unit tests, all packages
make integration                            # docker-required tests (1C/1D + lab mini-round)
make lint                                   # ruff + mypy + shellcheck + go vet

# Stage 2 lab:
make images                                 # build pentestlab/* images (llama-server ~15 min)
make lab-up                                 # deploy round 0 via containerlab
make ui                                     # dashboard at http://127.0.0.1:8088

# Stage 3 collection:
make collect                                # run_lab.py --mode inference --rounds 25
make collect-resume ROUND=7                 # [TOTAL=25 FIREWALL=coraza ...]
make collect-muse-all                       # muse-glimmer variants -> muse_dataset/
make validate

# Stage 3 Coraza engine (mirrors the BunkerWeb datasets 1:1):
make image-fw-coraza                        # build pentestlab/fw-coraza
make collect-coraza-all                     # -> qwen_dataset_coraza/ + muse_dataset_coraza/
make compare-engines DEST=logs/compare.md   # BunkerWeb vs Coraza apples-to-apples

# Stage 3B aggregation (Unsloth SFT):
make sft-datasets                           # -> attacker_train.json + defender_train.json
make sft-datasets-validate                  # schema + selection + chat-template checks

# Stage 4 SFT (Unsloth Qwen3.8-27B; train in Colab per SFT_pentest_network/README.md):
make sft-train DRY_RUN=1                    # resolve GPU/precision plan (CPU-safe)
make test PKG=SFT_pentest_network           # CPU unit tests
make sft-verify                             # artifact + weights-differ checks

# Stage 5 GRPO RL (all RL inference/training on the DO MI300X; local arena + mixed per role):
make rl-plan                                # resolve model/LoRA/batch algebra (CPU-safe)
make rl-bootstrap RL_REMOTE=root@<do-ip>    # one-time GPU-host setup (Unsloth AMD, SFT v3, serve)
make rl-rounds RL_REMOTE=root@<do-ip>       # 3-round loop: local rollouts + remote GRPO
make rl-seed AGENT=attacker                 # SFT v3 starting policy -> models/rl (+ arena volume)
make rl-serve                               # (GPU host) serve both policies: :8080 / :8081
make rl-rollouts ROUND=0 AGENT=attacker K=4 # live on-policy rollouts -> qwen_rl_dataset/ (local arena)
make rl-sync RL_REMOTE=root@<do-ip>         # ship rollouts to the MI300X training host
make rl-train ROUND=0 AGENT=attacker        # GRPO on the rollouts (SMOKE=1 DRY_RUN=1)
make rl-verify                              # adapter + weights-differ + atk!=def checks
python llm_pentest_network/run_lab.py --mode rl --rounds 25 --rollouts-only  # UI/rollout half
make rl-amd-setup                           # MI300X/DigitalOcean ROCm stack (optional)
```

Requires system packages: `tshark` (Wireshark CLI), `text2pcap` (test
fixtures), `nmap` (Stage 1C), `metasploit-framework` (Stage 1B, only for
live tests), `docker` (lab; containerlab runs dockerized — no root needed).

## Layout

- `pcap_to_md_mcp_server/` — Stage 1A MCP server + converters
- `metasploit_mcp_server/` — Stage 1B Metasploit RPC client + MCP server
- `nmap_skill/` — Stage 1C nmap skill (SKILL.md + wrappers + XML parser)
- `wireshark_skill/` — Stage 1D capture skill (SKILL.md + capture/triage)
- `scapy_skill/` — Stage 1E raw-packet skill (SKILL.md + arp/spoof/sniff/ping)
- `nuclei_skill/` — Stage 1F nuclei skill (SKILL.md + air-gap-safe wrappers + JSONL digest)
- `zap_skill/` — Stage 1G OWASP ZAP DAST skill (SKILL.md + wrappers + daemon + alerts digest)
- `llm_pentest_network/` — Stage 2/3 lab framework (containerlab topology,
  agents, judge, phases, UI) + `clab.sh` dockerized containerlab wrapper
- `SFT_pentest_network/` — Stage 4 Unsloth SFT of Qwen3.8-27B (attacker/defender;
  FP8/Q4, Colab notebook, export/promote into the arena)
- `RL_pentest_network/` — Stage 5 Unsloth GRPO (judge-backed rewards, live/offline
  rollouts, adapter verification, export/promote into the arena)
- `qwen_dataset/`, `muse_dataset/` (`datasets/` + `dataset_*` collection
  outputs) and their Coraza mirrors `qwen_dataset_coraza/`,
  `muse_dataset_coraza/`; `captures/`, `models/`, `sft_runs/`, `rl_runs/` —
  gitignored outputs (Stages 3–5, model weights/checkpoints)
- `docs/` — research notes and ops runbook
