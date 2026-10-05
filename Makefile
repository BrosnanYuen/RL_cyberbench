# LLM Red-Team / Blue-Team Pentest RL Arena — root makefile
# Stage 1: pcap_to_md (1A), metasploit_mcp (1B), nmap_skill (1C), wireshark_skill (1D)
# Stage 2/3: llm_pentest_network (lab framework, images, inference collection)

PY         ?= python3
VENV       ?= .venv
BIN        := $(VENV)/bin
PKG        ?= all
PKGS       := pcap_to_md_mcp_server metasploit_mcp_server nmap_skill wireshark_skill scapy_skill nuclei_skill zap_skill llm_pentest_network SFT_pentest_network RL_pentest_network
LABDIR     := llm_pentest_network
SFTDIR     := SFT_pentest_network
RLDIR      := RL_pentest_network

ifeq ($(PKG),all)
TEST_PKGS  := $(PKGS)
else
TEST_PKGS  := $(PKG)
endif

.PHONY: help
help:
	@echo "Targets: test [PKG=] | integration [PKG=] | lint | fmt | venv"
	@echo "         images | image-agent | image-llama | lab-up | lab-down | collect | ui"
	@echo "         collect-low-thinking | collect-medium | collect-xhigh"
	@echo "         collect-metasploit | collect-scapy | collect-nuclei | collect-zap | validate [DATASET=]"
	@echo "         collect-muse[-low-thinking|-medium|-xhigh|-metasploit|-scapy|-nuclei|-zap] | collect-muse-all"
	@echo "         collect-coraza-* | collect-coraza-muse-* | collect-coraza-all"
	@echo "         compare-engines [DEST=]  # bunkerweb vs coraza apples-to-apples report"
	@echo "         sft-datasets [ROOTS=] [SFT_OUT=] | sft-datasets-validate [SFT_TEMPLATE=]"
	@echo "         sft-train [AGENT=] [SFT_PRECISION=] [SMOKE=1] [DRY_RUN=1] | sft-verify [SFT_RUNS=] | sft-notebook"
	@echo "         rl-plan | rl-rollouts [ROUND= AGENT= K=] | rl-train [ROUND= AGENT= MODE= SMOKE=1 DRY_RUN=1]"
	@echo "         rl-seed [AGENT=] | rl-sync [RL_REMOTE=] | rl-serve [ACTION=] | rl-bootstrap [RL_REMOTE=] | rl-rounds [RL_REMOTE= ROUNDS= K=] | rl-verify [RL_OUTPUT=] | rl-notebook | rl-amd-setup | train"

.PHONY: venv
venv:
	$(PY) -m venv $(VENV) && $(BIN)/pip install -q pytest ruff mypy mcp shellcheck-py pyyaml

.PHONY: test
test:
	@for p in $(TEST_PKGS); do \
		if [ -d "$$p/tests" ]; then \
			echo "== pytest $$p (unit) =="; \
			$(BIN)/pytest $$p/tests -m "not integration and not gpu" -q || exit 1; \
		fi; \
	done

.PHONY: integration
integration:
	@for p in $(TEST_PKGS); do \
		if [ -d "$$p/tests" ]; then \
			echo "== pytest $$p (integration) =="; \
			$(BIN)/pytest $$p/tests -m integration $(if $(K),,-q); \
			rc=$$?; if [ $$rc -ne 0 ] && [ $$rc -ne 5 ]; then exit 1; fi; \
		fi; \
	done

.PHONY: lint
lint:
	$(BIN)/ruff check .
	$(BIN)/mypy --ignore-missing-imports --check-untyped-defs --explicit-package-bases \
		pcap_to_md_mcp_server metasploit_mcp_server nmap_skill wireshark_skill scapy_skill nuclei_skill zap_skill llm_pentest_network SFT_pentest_network RL_pentest_network \
		2>/dev/null || $(BIN)/mypy --ignore-missing-imports --check-untyped-defs \
		--explicit-package-bases llm_pentest_network SFT_pentest_network RL_pentest_network
	@if [ -x "$(BIN)/shellcheck" ]; then \
		$(BIN)/shellcheck nmap_skill/scripts/*.sh wireshark_skill/scripts/*.sh nuclei_skill/scripts/*.sh zap_skill/scripts/*.sh $(LABDIR)/clab.sh $(LABDIR)/scripts/*.sh; \
	else \
		echo "shellcheck not installed in $(VENV) — skipping"; \
	fi
	@docker run --rm -v "$$PWD:/src" -w /src golang:1.26-alpine sh -c \
		"cd llm_pentest_network/images/webserv && go vet ./... 2>/dev/null; \
		 cd ../innoclient && go vet ./... 2>/dev/null; \
		 cd ../fw-coraza && go vet ./... 2>/dev/null" || echo "go vet skipped (no go mod deps cached)"

.PHONY: fmt
fmt:
	$(BIN)/ruff format . && $(BIN)/ruff check --fix .

# ---------------- Stage 2/3 lab targets ----------------

.PHONY: images
images:
	bash $(LABDIR)/scripts/build_images.sh all

.PHONY: image-webserv
image-webserv:
	bash $(LABDIR)/scripts/build_images.sh webserv

.PHONY: image-innoclient
image-innoclient:
	bash $(LABDIR)/scripts/build_images.sh innoclient

.PHONY: image-fw-logger
image-fw-logger:
	bash $(LABDIR)/scripts/build_images.sh fw-logger

.PHONY: image-fw-coraza
image-fw-coraza:
	bash $(LABDIR)/scripts/build_images.sh fw-coraza

.PHONY: image-agent
image-agent:
	bash $(LABDIR)/scripts/build_images.sh agent-kali

.PHONY: image-llama
image-llama:
	bash $(LABDIR)/scripts/build_images.sh llama-server

.PHONY: image-orchestrator
image-orchestrator:
	bash $(LABDIR)/scripts/build_images.sh orchestrator

.PHONY: lab-up
lab-up:
	$(BIN)/python $(LABDIR)/run_lab.py --deploy-only

.PHONY: lab-down
lab-down:
	bash $(LABDIR)/scripts/lab_down.sh

DATASET    ?= qwen_dataset/datasets
CAPTURES   ?= captures
THINKING   ?=
STRATEGY   ?=
PROFILE    ?=
FIREWALL   ?=
ROUNDS     ?= 25
FRESH      ?=

.PHONY: collect
collect:  ## Stage 3: inference collection (DATASET= CAPTURES= THINKING= STRATEGY= PROFILE= FIREWALL= ROUNDS= FRESH=)
	$(BIN)/python $(LABDIR)/run_lab.py --mode inference --rounds $(ROUNDS) \
		--datasets-dir $(DATASET) --captures-dir $(CAPTURES) \
		--event-log $(DATASET)/events.jsonl \
		$(if $(THINKING),--thinking $(THINKING)) \
		$(if $(STRATEGY),--attack-strategy $(STRATEGY)) \
		$(if $(PROFILE),--profile $(PROFILE)) \
		$(if $(FIREWALL),--firewall-engine $(FIREWALL)) \
		$(if $(FRESH),--fresh)

# Stage 3 collection variants: one clean dataset per thinking level / strategy
# (FRESH wipes agent/firewall state volumes so each dataset starts with no memory)
.PHONY: collect-low-thinking collect-medium collect-xhigh collect-metasploit collect-scapy
collect-low-thinking: DATASET := qwen_dataset/dataset_low_thinking
collect-low-thinking: CAPTURES := qwen_dataset/dataset_low_thinking/captures
collect-low-thinking: THINKING := low
collect-low-thinking: FRESH := 1
collect-low-thinking: collect

collect-medium: DATASET := qwen_dataset/dataset_medium
collect-medium: CAPTURES := qwen_dataset/dataset_medium/captures
collect-medium: THINKING := medium
collect-medium: FRESH := 1
collect-medium: collect

collect-xhigh: DATASET := qwen_dataset/dataset_xhigh
collect-xhigh: CAPTURES := qwen_dataset/dataset_xhigh/captures
collect-xhigh: THINKING := xhigh
collect-xhigh: FRESH := 1
collect-xhigh: collect

collect-metasploit: DATASET := qwen_dataset/dataset_metasploit
collect-metasploit: CAPTURES := qwen_dataset/dataset_metasploit/captures
collect-metasploit: STRATEGY := metasploit
collect-metasploit: FRESH := 1
collect-metasploit: collect

collect-scapy: DATASET := qwen_dataset/dataset_scapy
collect-scapy: CAPTURES := qwen_dataset/dataset_scapy/captures
collect-scapy: STRATEGY := scapy
collect-scapy: FRESH := 1
collect-scapy: collect

collect-nuclei: DATASET := qwen_dataset/dataset_nuclei
collect-nuclei: CAPTURES := qwen_dataset/dataset_nuclei/captures
collect-nuclei: STRATEGY := nuclei
collect-nuclei: FRESH := 1
collect-nuclei: collect

collect-zap: DATASET := qwen_dataset/dataset_zap
collect-zap: CAPTURES := qwen_dataset/dataset_zap/captures
collect-zap: STRATEGY := zap
collect-zap: FRESH := 1
collect-zap: collect

# Muse-Glimmer-30B profile variants (DFlash drafter) -> muse_dataset/
# Same variant matrix as the qwen targets; the profile is forced on the CLI.
MUSE_PROFILE := muse-glimmer-30b-dflash

.PHONY: collect-muse collect-muse-low-thinking collect-muse-medium collect-muse-xhigh
.PHONY: collect-muse-metasploit collect-muse-scapy collect-muse-nuclei collect-muse-zap
.PHONY: collect-muse-all

collect-muse: DATASET := muse_dataset/datasets
collect-muse: CAPTURES := muse_dataset/datasets/captures
collect-muse: PROFILE := $(MUSE_PROFILE)
collect-muse: FRESH := 1
collect-muse: collect

collect-muse-low-thinking: DATASET := muse_dataset/dataset_low_thinking
collect-muse-low-thinking: CAPTURES := muse_dataset/dataset_low_thinking/captures
collect-muse-low-thinking: THINKING := low
collect-muse-low-thinking: PROFILE := $(MUSE_PROFILE)
collect-muse-low-thinking: FRESH := 1
collect-muse-low-thinking: collect

collect-muse-medium: DATASET := muse_dataset/dataset_medium
collect-muse-medium: CAPTURES := muse_dataset/dataset_medium/captures
collect-muse-medium: THINKING := medium
collect-muse-medium: PROFILE := $(MUSE_PROFILE)
collect-muse-medium: FRESH := 1
collect-muse-medium: collect

collect-muse-xhigh: DATASET := muse_dataset/dataset_xhigh
collect-muse-xhigh: CAPTURES := muse_dataset/dataset_xhigh/captures
collect-muse-xhigh: THINKING := xhigh
collect-muse-xhigh: PROFILE := $(MUSE_PROFILE)
collect-muse-xhigh: FRESH := 1
collect-muse-xhigh: collect

collect-muse-metasploit: DATASET := muse_dataset/dataset_metasploit
collect-muse-metasploit: CAPTURES := muse_dataset/dataset_metasploit/captures
collect-muse-metasploit: STRATEGY := metasploit
collect-muse-metasploit: PROFILE := $(MUSE_PROFILE)
collect-muse-metasploit: FRESH := 1
collect-muse-metasploit: collect

collect-muse-scapy: DATASET := muse_dataset/dataset_scapy
collect-muse-scapy: CAPTURES := muse_dataset/dataset_scapy/captures
collect-muse-scapy: STRATEGY := scapy
collect-muse-scapy: PROFILE := $(MUSE_PROFILE)
collect-muse-scapy: FRESH := 1
collect-muse-scapy: collect

collect-muse-nuclei: DATASET := muse_dataset/dataset_nuclei
collect-muse-nuclei: CAPTURES := muse_dataset/dataset_nuclei/captures
collect-muse-nuclei: STRATEGY := nuclei
collect-muse-nuclei: PROFILE := $(MUSE_PROFILE)
collect-muse-nuclei: FRESH := 1
collect-muse-nuclei: collect

collect-muse-zap: DATASET := muse_dataset/dataset_zap
collect-muse-zap: CAPTURES := muse_dataset/dataset_zap/captures
collect-muse-zap: STRATEGY := zap
collect-muse-zap: PROFILE := $(MUSE_PROFILE)
collect-muse-zap: FRESH := 1
collect-muse-zap: collect

collect-muse-all:  ## Stage 3: every muse-glimmer variant, sequentially
	bash $(LABDIR)/scripts/collect_muse_all.sh

# ---------------- Coraza mirror collection ----------------
# Same matrix/settings as the bunkerweb runs (only firewall.engine differs);
# round counts mirror the rounds actually collected on bunkerweb. Datasets
# land in sibling roots so `scripts/compare_engines.py` can pair them 1:1.
CORAZA_QWEN ?= qwen_dataset_coraza
CORAZA_MUSE ?= muse_dataset_coraza

.PHONY: collect-coraza-low-thinking collect-coraza-medium collect-coraza-xhigh
.PHONY: collect-coraza-metasploit collect-coraza-scapy collect-coraza-nuclei collect-coraza-zap
.PHONY: collect-coraza-muse collect-coraza-muse-low-thinking collect-coraza-muse-medium
.PHONY: collect-coraza-muse-xhigh collect-coraza-muse-metasploit collect-coraza-muse-scapy
.PHONY: collect-coraza-muse-nuclei collect-coraza-muse-zap
.PHONY: collect-coraza-all

collect-coraza-low-thinking: DATASET := $(CORAZA_QWEN)/dataset_low_thinking
collect-coraza-low-thinking: CAPTURES := $(CORAZA_QWEN)/dataset_low_thinking/captures
collect-coraza-low-thinking: THINKING := low
collect-coraza-low-thinking: ROUNDS := 3
collect-coraza-low-thinking: FIREWALL := coraza
collect-coraza-low-thinking: FRESH := 1
collect-coraza-low-thinking: collect

collect-coraza-medium: DATASET := $(CORAZA_QWEN)/dataset_medium
collect-coraza-medium: CAPTURES := $(CORAZA_QWEN)/dataset_medium/captures
collect-coraza-medium: THINKING := medium
collect-coraza-medium: ROUNDS := 3
collect-coraza-medium: FIREWALL := coraza
collect-coraza-medium: FRESH := 1
collect-coraza-medium: collect

collect-coraza-xhigh: DATASET := $(CORAZA_QWEN)/dataset_xhigh
collect-coraza-xhigh: CAPTURES := $(CORAZA_QWEN)/dataset_xhigh/captures
collect-coraza-xhigh: THINKING := xhigh
collect-coraza-xhigh: ROUNDS := 3
collect-coraza-xhigh: FIREWALL := coraza
collect-coraza-xhigh: FRESH := 1
collect-coraza-xhigh: collect

collect-coraza-metasploit: DATASET := $(CORAZA_QWEN)/dataset_metasploit
collect-coraza-metasploit: CAPTURES := $(CORAZA_QWEN)/dataset_metasploit/captures
collect-coraza-metasploit: STRATEGY := metasploit
collect-coraza-metasploit: ROUNDS := 3
collect-coraza-metasploit: FIREWALL := coraza
collect-coraza-metasploit: FRESH := 1
collect-coraza-metasploit: collect

collect-coraza-scapy: DATASET := $(CORAZA_QWEN)/dataset_scapy
collect-coraza-scapy: CAPTURES := $(CORAZA_QWEN)/dataset_scapy/captures
collect-coraza-scapy: STRATEGY := scapy
collect-coraza-scapy: ROUNDS := 3
collect-coraza-scapy: FIREWALL := coraza
collect-coraza-scapy: FRESH := 1
collect-coraza-scapy: collect

collect-coraza-nuclei: DATASET := $(CORAZA_QWEN)/dataset_nuclei
collect-coraza-nuclei: CAPTURES := $(CORAZA_QWEN)/dataset_nuclei/captures
collect-coraza-nuclei: STRATEGY := nuclei
collect-coraza-nuclei: ROUNDS := 3
collect-coraza-nuclei: FIREWALL := coraza
collect-coraza-nuclei: FRESH := 1
collect-coraza-nuclei: collect

collect-coraza-zap: DATASET := $(CORAZA_QWEN)/dataset_zap
collect-coraza-zap: CAPTURES := $(CORAZA_QWEN)/dataset_zap/captures
collect-coraza-zap: STRATEGY := zap
collect-coraza-zap: ROUNDS := 3
collect-coraza-zap: FIREWALL := coraza
collect-coraza-zap: FRESH := 1
collect-coraza-zap: collect

# muse twins: 3 rounds each (mirror), except default=6 and scapy=14 (the
# rounds bunkerweb actually completed before the run was interrupted).
collect-coraza-muse: DATASET := $(CORAZA_MUSE)/datasets
collect-coraza-muse: CAPTURES := $(CORAZA_MUSE)/datasets/captures
collect-coraza-muse: ROUNDS := 6
collect-coraza-muse: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse: FIREWALL := coraza
collect-coraza-muse: FRESH := 1
collect-coraza-muse: collect

collect-coraza-muse-low-thinking: DATASET := $(CORAZA_MUSE)/dataset_low_thinking
collect-coraza-muse-low-thinking: CAPTURES := $(CORAZA_MUSE)/dataset_low_thinking/captures
collect-coraza-muse-low-thinking: THINKING := low
collect-coraza-muse-low-thinking: ROUNDS := 3
collect-coraza-muse-low-thinking: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse-low-thinking: FIREWALL := coraza
collect-coraza-muse-low-thinking: FRESH := 1
collect-coraza-muse-low-thinking: collect

collect-coraza-muse-medium: DATASET := $(CORAZA_MUSE)/dataset_medium
collect-coraza-muse-medium: CAPTURES := $(CORAZA_MUSE)/dataset_medium/captures
collect-coraza-muse-medium: THINKING := medium
collect-coraza-muse-medium: ROUNDS := 3
collect-coraza-muse-medium: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse-medium: FIREWALL := coraza
collect-coraza-muse-medium: FRESH := 1
collect-coraza-muse-medium: collect

collect-coraza-muse-xhigh: DATASET := $(CORAZA_MUSE)/dataset_xhigh
collect-coraza-muse-xhigh: CAPTURES := $(CORAZA_MUSE)/dataset_xhigh/captures
collect-coraza-muse-xhigh: THINKING := xhigh
collect-coraza-muse-xhigh: ROUNDS := 3
collect-coraza-muse-xhigh: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse-xhigh: FIREWALL := coraza
collect-coraza-muse-xhigh: FRESH := 1
collect-coraza-muse-xhigh: collect

collect-coraza-muse-metasploit: DATASET := $(CORAZA_MUSE)/dataset_metasploit
collect-coraza-muse-metasploit: CAPTURES := $(CORAZA_MUSE)/dataset_metasploit/captures
collect-coraza-muse-metasploit: STRATEGY := metasploit
collect-coraza-muse-metasploit: ROUNDS := 3
collect-coraza-muse-metasploit: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse-metasploit: FIREWALL := coraza
collect-coraza-muse-metasploit: FRESH := 1
collect-coraza-muse-metasploit: collect

collect-coraza-muse-scapy: DATASET := $(CORAZA_MUSE)/dataset_scapy
collect-coraza-muse-scapy: CAPTURES := $(CORAZA_MUSE)/dataset_scapy/captures
collect-coraza-muse-scapy: STRATEGY := scapy
collect-coraza-muse-scapy: ROUNDS := 14
collect-coraza-muse-scapy: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse-scapy: FIREWALL := coraza
collect-coraza-muse-scapy: FRESH := 1
collect-coraza-muse-scapy: collect

collect-coraza-muse-nuclei: DATASET := $(CORAZA_MUSE)/dataset_nuclei
collect-coraza-muse-nuclei: CAPTURES := $(CORAZA_MUSE)/dataset_nuclei/captures
collect-coraza-muse-nuclei: STRATEGY := nuclei
collect-coraza-muse-nuclei: ROUNDS := 3
collect-coraza-muse-nuclei: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse-nuclei: FIREWALL := coraza
collect-coraza-muse-nuclei: FRESH := 1
collect-coraza-muse-nuclei: collect

collect-coraza-muse-zap: DATASET := $(CORAZA_MUSE)/dataset_zap
collect-coraza-muse-zap: CAPTURES := $(CORAZA_MUSE)/dataset_zap/captures
collect-coraza-muse-zap: STRATEGY := zap
collect-coraza-muse-zap: ROUNDS := 3
collect-coraza-muse-zap: PROFILE := $(MUSE_PROFILE)
collect-coraza-muse-zap: FIREWALL := coraza
collect-coraza-muse-zap: FRESH := 1
collect-coraza-muse-zap: collect

collect-coraza-all:  ## Stage 3: every coraza mirror dataset, sequentially
	bash $(LABDIR)/scripts/collect_coraza_all.sh

TOTAL ?= 25

.PHONY: collect-resume
collect-resume:
	@test -n "$(ROUND)" || (echo "usage: make collect-resume ROUND=N [TOTAL=25] [DATASET=...] [CAPTURES=...] [THINKING=...] [STRATEGY=...] [FIREWALL=...]" >&2; exit 2)
	$(BIN)/python $(LABDIR)/run_lab.py --mode inference --rounds $$(( $(TOTAL) - $(ROUND) )) --resume $(ROUND) \
		--datasets-dir $(DATASET) --captures-dir $(CAPTURES) --event-log $(DATASET)/events.jsonl \
		$(if $(THINKING),--thinking $(THINKING)) \
		$(if $(STRATEGY),--attack-strategy $(STRATEGY)) \
		$(if $(PROFILE),--profile $(PROFILE)) \
		$(if $(FIREWALL),--firewall-engine $(FIREWALL))

.PHONY: validate
validate:
	$(BIN)/python $(LABDIR)/lab/dataset.py --validate --rounds 25 --datasets-dir $(DATASET) || true

DEST ?=
.PHONY: compare-engines
compare-engines:  ## Apples-to-apples bunkerweb vs coraza report (DEST=path)
	$(BIN)/python $(LABDIR)/scripts/compare_engines.py \
		$(if $(DEST),--out $(DEST)) $(if $(PER_ROUND),--per-round)

SFT_OUT      ?= .
SFT_ROOTS    ?= qwen_dataset muse_dataset qwen_dataset_coraza muse_dataset_coraza
SFT_TEMPLATE ?=

.PHONY: sft-datasets
sft-datasets:  ## Stage 3B: aggregate Unsloth SFT files (ROOTS= SFT_OUT=)
	$(BIN)/python $(LABDIR)/lab/sft_dataset.py --build --out-dir $(SFT_OUT) --roots $(SFT_ROOTS)

.PHONY: sft-datasets-validate
sft-datasets-validate:  ## Validate attacker_train.json / defender_train.json (SFT_TEMPLATE=path.jinja)
	$(BIN)/python $(LABDIR)/lab/sft_dataset.py --validate --out-dir $(SFT_OUT) \
		$(if $(SFT_TEMPLATE),--template $(SFT_TEMPLATE))

# ---------------- Stage 4 SFT (Unsloth, Qwen3.8-27B) ----------------
# Training needs the optional stack (`pip install -e SFT_pentest_network[train]`)
# and a GPU; DRY_RUN=1 and `make test PKG=SFT_pentest_network` are CPU-only.

SFT_RUNS      ?= sft_runs
SFT_AGENT     ?= both
SFT_PRECISION ?=

.PHONY: sft-train
sft-train:  ## Stage 4: Unsloth SFT (AGENT=both SFT_PRECISION=auto|fp8|4bit|16bit SMOKE=1 DRY_RUN=1)
	PYTHONPATH=$(SFTDIR) $(BIN)/python -m sft.train \
		--config $(SFTDIR)/configs/sft.default.yaml --agent $(SFT_AGENT) \
		$(if $(SFT_PRECISION),--precision $(SFT_PRECISION)) \
		$(if $(SMOKE),--smoke) $(if $(DRY_RUN),--dry-run) \
		$(if $(OUTPUT_ROOT),--output-root $(OUTPUT_ROOT))

.PHONY: sft-verify
sft-verify:  ## Stage 4: verify SFT runs (SFT_RUNS=sft_runs)
	PYTHONPATH=$(SFTDIR) $(BIN)/python -m sft.verify --all --output-root $(SFT_RUNS)

.PHONY: sft-notebook
sft-notebook:  ## Stage 4: regenerate the Colab notebook from the builder
	$(BIN)/python $(SFTDIR)/scripts/build_colab_notebook.py

# ---------------- Stage 5 RL (Unsloth GRPO) ----------------
# Training needs the optional stack (`pip install -e RL_pentest_network[train]`)
# and a GPU; DRY_RUN=1 and `make test PKG=RL_pentest_network` are CPU-only.

RL_CONFIG    ?= $(RLDIR)/configs/rl.default.yaml
RL_AGENT     ?= auto
RL_MODE      ?= offline
RL_OUTPUT    ?= rl_runs
RL_LOG_ROOT  ?= qwen_rl_dataset
RL_REMOTE    ?=                             # user@host of the GPU training host (DO MI300X)
RL_REMOTE_REPO ?= /root/RL_cyberbench       # repo checkout on the GPU host
RL_REMOTE_DIR ?= $(RL_REMOTE_REPO)/$(RL_LOG_ROOT)
RL_SETUP_ARGS ?= --seed --serve             # extra args for setup_do_gpu_host.sh

.PHONY: rl-plan
rl-plan:  ## Stage 5: resolve the GRPO plan without loading the model (CPU-safe)
	PYTHONPATH=$(RLDIR):$(LABDIR) $(BIN)/python -m rl.train --config $(RL_CONFIG) --rounds 1 --dry-run

.PHONY: rl-rollouts
rl-rollouts:  ## Stage 5: build K live on-policy rollouts (ROUND= AGENT= K=)
	@test -n "$(ROUND)" -a -n "$(AGENT)" || (echo "usage: make rl-rollouts ROUND=0 AGENT=attacker [K=4]" >&2; exit 2)
	PYTHONPATH=$(RLDIR):$(LABDIR) $(BIN)/python -m rl.rollouts --config $(RL_CONFIG) \
		--round $(ROUND) --agent $(AGENT) $(if $(K),--k $(K))

.PHONY: rl-train
rl-train:  ## Stage 5: GRPO training (ROUND= AGENT=auto MODE=offline ROLLOUTS= SMOKE=1 DRY_RUN=1)
	PYTHONPATH=$(RLDIR):$(LABDIR) $(BIN)/python -m rl.train --config $(RL_CONFIG) \
		$(if $(ROUND),--round $(ROUND),--rounds 1) --agent $(RL_AGENT) --mode $(RL_MODE) \
		$(if $(ROLLOUTS),--rollouts $(ROLLOUTS)) \
		--output-root $(RL_OUTPUT) --log-root $(RL_LOG_ROOT) \
		$(if $(SMOKE),--smoke) $(if $(DRY_RUN),--dry-run)

.PHONY: rl-verify
rl-verify:  ## Stage 5: verify GRPO runs (RL_OUTPUT=rl_runs)
	PYTHONPATH=$(RLDIR) $(BIN)/python -m rl.verify --all --output-root $(RL_OUTPUT)

.PHONY: rl-seed
rl-seed:  ## Stage 5: seed the arena with the SFT v3 starting policy (AGENT=attacker|defender)
	@test -n "$(AGENT)" || (echo "usage: make rl-seed AGENT=attacker|defender" >&2; exit 2)
	PYTHONPATH=$(RLDIR):$(LABDIR) $(BIN)/python -m rl.export --from-adapter \
		--agent $(AGENT) --config $(RL_CONFIG) --seed-volume --restart-sidecar \
		$(if $(DRY_RUN),--dry-run)

.PHONY: rl-amd-setup
rl-amd-setup:  ## Stage 5: MI300X ROCm stack (Unsloth AMD installer + pinned deps)
	bash $(RLDIR)/scripts/setup_amd_mi300x.sh

.PHONY: rl-sync
rl-sync:  ## Stage 5: ship local rollout JSONL to the GPU training host (RL_REMOTE=user@host)
	@test -n "$(RL_REMOTE)" || (echo "usage: make rl-sync RL_REMOTE=user@host [RL_REMOTE_DIR=...]" >&2; exit 2)
	rsync -az --info=progress2 $(RL_LOG_ROOT)/ $(RL_REMOTE):$(RL_REMOTE_DIR)/

.PHONY: rl-serve
rl-serve:  ## Stage 5: serve both policies on the DO MI300X (ACTION=start|stop|status)
	bash $(RLDIR)/scripts/serve_mi300x_inference.sh $(or $(ACTION),start)

.PHONY: rl-bootstrap
rl-bootstrap:  ## Stage 5: sync repo + bootstrap the DO GPU host (RL_REMOTE=user@host [RL_SETUP_ARGS=])
	@test -n "$(RL_REMOTE)" || (echo "usage: make rl-bootstrap RL_REMOTE=user@host [RL_SETUP_ARGS='--seed --serve']" >&2; exit 2)
	rsync -az --info=progress2 -e "ssh -o BatchMode=yes" \
		--exclude '.venv' --exclude '.git' --exclude '__pycache__' \
		--exclude 'models' --exclude 'muse_dataset' --exclude 'qwen_sft_dataset' \
		--exclude 'qwen_dataset' --exclude 'qwen_sft_dataset_coraza' \
		--exclude 'qwen_dataset_coraza' --exclude 'muse_dataset_coraza' \
		--exclude 'captures' --exclude 'llama.cpp' --exclude 'logs' \
		--exclude 'runtime' --exclude 'rl_runs' --exclude '*.gguf' \
		--exclude 'qwen_rl_dataset' \
		./ $(RL_REMOTE):$(RL_REMOTE_REPO)/
	ssh -o BatchMode=yes $(RL_REMOTE) \
		"cd $(RL_REMOTE_REPO) && bash RL_pentest_network/scripts/setup_do_gpu_host.sh $(RL_SETUP_ARGS)"

.PHONY: rl-rounds
rl-rounds:  ## Stage 5: campaign loop (RL_REMOTE= ROUNDS=3 K=4; local rollouts + remote GRPO)
	@test -n "$(RL_REMOTE)" || (echo "usage: make rl-rounds RL_REMOTE=user@host [ROUNDS=3 K=4]" >&2; exit 2)
	bash $(RLDIR)/scripts/run_rl_rounds.sh --remote $(RL_REMOTE) \
		--rounds $(or $(ROUNDS),3) --k $(or $(K),4)

.PHONY: rl-notebook
rl-notebook:  ## Stage 5: regenerate the Colab notebook from the builder
	$(BIN)/python $(RLDIR)/scripts/build_colab_notebook.py

.PHONY: train
train: rl-train  ## Stage 5 alias: full GRPO training run

.PHONY: ui
ui:
	$(BIN)/uvicorn ui.app:app --host 127.0.0.1 --port 8088 --app-dir $(LABDIR)
