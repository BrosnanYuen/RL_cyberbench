


The project has 4 stages:


have ./README.md files for all folders

try to write in python if not can use javascript

Stage 1: 
Write a pcap or tcp dump converter for converting the summaries of pcaps to markdown  (only the summary of each packet in a pcap to one summary.md tshark summary)
Write a pcap or tcp dump converter for converting entire pcap to markdown (full conversion of each packet of each pcap to markdown format and to many files)
for use in the attacker and defender LLMs ./pcap_to_md_mcp_server/
Write a Metasploit Framework mcp server for use in the attacker and defender LLMs ./metasploit_mcp_server/
Write a nmap skill detailing how to use nmap to detect vulnebilities for use in the attacker and defender LLMs that can scan the network ./nmap_skill/
Write a wireshark skill detailing how to use for collecting traffic for use in the attacker and defender LLMs ./wireshark_skill/


Stage 2: Write the framework for setting up the network and clients firewall server docker and everything else and deploying the LLM inference (NOT TRAINING)  and collecting LLM inputs and outputs  save them to a file for training dataset
in  ./llm_pentest_network/

Stage 3A: Run the framework for inference only for 25 rounds to collect  data for training dataset
Stage 3B: Aggregate the collected datasets into Unsloth supervised finetuning (SFT) training files:
  - attacker_train.json : all attacker data from every dataset round where the attacker score > 0
  - defender_train.json : all defender data from every dataset round where the attacker score > 0 (from the attack phase) AND the defender score > 0 (from the defend phase)
  - both files must load directly into Unsloth SFTTrainer (messages format; exact schema in PLAN.md STAGE 3B)
  - assistant reasoning goes in a separate reasoning_content field; tool_call arguments must be JSON objects (not JSON strings) - the model's Unsloth chat template enforces this

Stage 5: Write the framework for reinforcement learning training scenario  in  ./RL_pentest_network/


write unit and integration tests for all of them


Goal:
Write code for reinforcement learning training scenario,
where the attacker LLM's goal is to attack a firewall and crash it or steal secret data from webserver
and the defender LLM's goal is to defend a firewall and allow client to access webserver and client will get secret data

Must also collect all LLM inputs and outputs and tool calls and save them to a file for training dataset

Use unsloth GRPO

vLLM and training will be hosted on google colab or locally



USE containerlab if possible for network deployment, if not then can use regular docker containers
https://containerlab.dev/manual/kinds/
https://containerlab.dev/quickstart/
https://containerlab.dev/manual/topo-def-file/


ALL LLMS and code must only run in docker  and never escape confinement
create internal network in docker and no packet should escape to the internet

Use this firewall
https://github.com/bunkerity/bunkerweb

There can be multiple attackers and clients on different random IPs
Defender doesn't know the IPs at the start

There are as many attacker IPs as client IPs. there should be atlest two attacker IPs but only 1 LLM attacker docker
Only 1 LLM defender docker

limit attacker LLM docker 8 GB RAM and 50 GB disk but unlimited VRAM
limit defender LLM docker 8 GB RAM and 50 GB disk but unlimited VRAM
limit firewall LLM docker 8 GB RAM and 25 GB disk and no GPU access
limit client docker 2 GB RAM and 25 GB disk and no GPU access
limit webserver docker 2 GB RAM and 25 GB disk and no GPU access


Attacker LLM must use official kali linux docker images
Defender LLM must use official kali linux docker images

Innocent Client Docker, firewall docker and server docker can use any other image like official ubuntu images


Attacker LLM Docker
Attacker IP 1  -----------------------------------------
                                                        |
Attacker IP 2  -----------------------------------------
                                                        |
                                                        V
Innocent Client Docker IP 1  ----------->  bunkerweb Firewall  Docker -------> Web server Docker 1
                                   |                    ^               |
Innocent Client Docker IP 2  ------                     |               -----> Web server Docker 2
                                                Defender LLM Docker

IP addresses will be randomized every round to prevent hardcoding
Clients should use any random IP in 192.160.1.1/16
Web server should use any random IP in 192.161.1.1/16

Attacker LLM Docker  only connects to Firewall Docker
Innocent Client Docker only connects to Firewall Docker
Firewall Docker only connects to Web server Docker, Attacker LLM Docker , Innocent Client Docker 

Attacker LLM Docker can only read source code of Innocent Client,   Firewall   , Web server , and Defender LLM 
Attacker LLM Docker cannot change source code of Innocent Client ,   Firewall   , Web server , and Defender LLM 

Defender LLM Docker can only read source code of Innocent Client ,   Firewall   , Web server , and Attacker LLM 
Defender LLM Docker can only change source code of Innocent Client ,   Firewall   , Web server 
Defender LLM Docker cannot change source code of attacks or Attacker LLM 

Web server have secret data that is randomized every round

Client and Web server  must be written in go lang only and should support HTTP1.1  HTTP2  HTTP3
Seed the firewall at the start with 1 obvious security vulnerability
Defender can use authentication or other methods to secure firewall

Network must be custimizable to support different network topologies in the future

USE [ pi.dev ](https://pi.dev/docs/latest) harness for attacker and defender LLM
and have 200K context limit.
attackers and defenders can write their own .md and pi MCP servers that are persistant to the next round
for attacking and defending

kvcache precision 8bit
vllm max seq len to 4

Use Qwen3.8-27B Q4 K M for testing for now but can use bigger models later
https://huggingface.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF/

Attacker LLM and Defender LLM should have different weights by the end of training
use atleast 4 threads to load LLM weights from HDD to RAM faster

Phase 0: Randomize 
IP addresses of all dockers will be randomized here every round to prevent hardcoding
Web server have secret data is randomized here every round

Phase 1: Attack 
Innocent Client,   Firewall   , Web server , and Defender LLM  source code must not be changed  but the code will run
Attacker LLM will look at the Innocent Client,   Firewall   , Web server , and Defender LLM source code
Attacker LLM write new code to attack firewall such that
Attacker will only know the firewall and webserver IPs
Attacker will not know secret data in webserver before running attack

Attacker Score:    +10 if attacker access web server and get secret data without authentication
                    +5 if attacker crash the firewall or webserver
                    +2 if DDOS the firewall and Innocent clients cannot access webserver to get secret data
                    +1 if innocent client IP or other IP is logged by firewall and is classified as attacker IP
                    -1 if real attacker IP is logged by firewall and is classified as attacker IP
                    -2 if the type of CWE/CVE attack is correctly classified by firewall
                    -5 if Innocent clientS manage to  access webserver and get secret data successfuly
                    -5 for refusal to do anything
                    -10 if run out of RAM or disk space
                    +0 reward if none of the above

attacker must put secret data in certain files like ./secret.json for scoring
innocent client must put secret data in certain files like ./secret.json for scoring
firewall must put logs in certain files like ./firewallog.json  and have certain format for scoring
THe judging must be determenistic and not LLM and if nothing happens then have a score of 0
the judge can be a text log parser that parses the .json

Phase 2: Randomize 
IP addresses of all dockers will be randomized here every round to prevent hardcoding
Web server have secret data is randomized here every round

Phase 3: Defend 
Attacker source code must not be changed  but the attacker code will run
Defender LLM will look at the Innocent Client,   Firewall   , Web server , and Attacker LLM source code
Defender LLM will modify the source to protect the Innocent Client,   Firewall   , Web server
Defender will not know attacker's IP but knows Innocent Client,   Firewall   , Web server's IP

Defender Score:     +10  if Innocent client manage to  access webserver and get secret data successfuly
                    +2  if the type of CWE/CVE attack is correctly classified by firewall
                    +1  if real attacker IP is logged by firewall and is classified as attacker IP
                    +1  if innocent IP is logged by firewall and is classified as innocent IP
                    -1  if innocent client IP or other IP is logged by firewall and is classified as attacker IP
                    -2  if real attacker IP is logged by firewall and is classified as innocent client IP
                    -2  if client cannot get secret data from webserver
                    -5  if attacker crash the firewall or webserver
                    -10 if attacker get webserver data without authentication
                    -5 for refusal to do anything
                    -10 if run out of RAM or disk space
                    +0 reward if none of the above

attacker must put secret data in certain files like ./secret.json for scoring
innocent client must put secret data in certain files like ./secret.json for scoring
firewall must put logs in certain files like ./firewallog.json  and have certain format for scoring
THe judging must be determenistic and not LLM and if nothing happens then have a score of 0
the judge can be a text log parser

Phase 4: RL Train
Train the Attacker and Defender LLMs and update their weights
Do not use warm up in training
use learning rate 4e-4 and the default LoRA weight initialization
(subsequent runs may warm-start from a previous adapter via lora.init_from)
verify the trained weights are different from initial weights
verify the attacker weights are different from defender weights

Round 0 has Phase 0 to Phase 3
Round 1 has Phase 0 to Phase 4
Round 2 has Phase 0 to Phase 3
Round 3 has Phase 0 to Phase 4
Round 4 has Phase 0 to Phase 4
and so on ....


Must have web UI for deployment of inference and RL training
One webpage for inference with network topology and status of LLM and docker and MCP and score in real time
have a button for running inference and stopping inference  and must collected LLM input and outputs to a file
Web UI must be custimizable to support different network topologies in the future

One webpage for RL training with network topology and status of LLM and docker and MCP and score in real time
and also the loss function and the number of steps in training and have a button for running RL and stopping RL  





