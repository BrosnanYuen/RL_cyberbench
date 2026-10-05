# Containerlab — Basic documentation (how to use)

> A condensed "getting started" guide, taken from the official Containerlab documentation at <https://containerlab.dev/> (docs version v0.79.0, retrieved 2026-09-08).
> This file intentionally covers only the basics. The full reference (user manual, all node kinds, command reference, lab examples, release notes) lives at <https://containerlab.dev/>.

---

## 1. What is Containerlab

Containerlab provides a CLI for orchestrating and managing **container-based networking labs**:

- it starts containers that run network operating systems (NOSes) such as Nokia SR Linux, Arista cEOS, Cisco XRd and many others, as well as arbitrary Linux containers,
- it builds a virtual wiring between the containers (topology links),
- it manages the lab's lifecycle (deploy, destroy, restart, etc.).

No software other than Docker is required on the lab host, and everything is driven by a single binary and a plain-text (YAML) topology file — which makes labs easy to script and use in CI.

### Use cases

- Labs and demos (no extra software beyond Docker on the host)
- Testing and CI (single-command lab provisioning from code-based definitions)
- Telemetry validation

---

## 2. Requirements

- A Linux server/VM
- [Docker](https://docs.docker.com/engine/install/) installed
- `sudo` privileges to run containerlab
- The container images used by the lab nodes (containerlab will try to pull images at runtime if they do not exist locally; images that are not in a public registry must be loaded manually — see [Images](#8-container-images))

---

## 3. Installation

The easiest way on RHEL- or Debian-based distros (Ubuntu 20.04+, Debian 11+, RHEL 9, CentOS Stream 9, Fedora Server 40, Rocky Linux) is the quick setup script, which installs Docker (docker-ce), docker compose, containerlab and the `gh` CLI in one go:

```bash
curl -sL https://containerlab.dev/setup | sudo -E bash -s "all"
```

If you only want one component, pass its name instead, e.g. to install only Docker:

```bash
curl -sL https://containerlab.dev/setup | sudo -E bash -s "install-docker"
```

> After the quick setup you may need to run `newgrp docker` (or log out/in) so `docker` works without `sudo`. The user running the quick install is automatically granted sudo-less containerlab operation.

Alternatively, install only containerlab (any Linux, latest release) with:

```bash
bash -c "$(curl -sL https://get.containerlab.dev)"
```

Verify the installation:

```bash
containerlab version
```

---

## 4. Topology definition file

A lab is defined in a *topology definition* file, conventionally named `*.clab.yml`. It describes the lab's **nodes** (with their kinds and container images), the **links** between them, and lab-level settings.

Example — two connected nodes (`srlceos01.clab.yml`):

```yaml
# topology documentation: http://containerlab.dev/lab-examples/srl-ceos/
name: srlceos01

topology:
  nodes:
    srl:
      kind: nokia_srlinux
      image: ghcr.io/nokia/srlinux:24.10
    ceos:
      kind: arista_ceos
      image: ceos:4.32.0F

  links:
    - endpoints: ["srl:ethernet-1/1", "ceos:eth1"]
```

Key parts of this file:

- `name` — the lab name (containers get names prefixed with `clab-<lab name>-`).
- `topology.nodes` — the set of nodes. Each node has:
  - `kind` — which NOS/container type it is (e.g. `nokia_srlinux`, `arista_ceos`, `linux`, ...). The kind determines the node's configuration and behavior. The full catalog of supported kinds is documented under <https://containerlab.dev/manual/kinds/>; common ones include `nokia_srlinux`, `arista_ceos`, `cisco_xrd`, `juniper_crpd`, `linux`, `frr`, `bridge`, `host`, etc.
  - `image` — the container image the node runs (same naming rules as Docker CLI: registry/organisation/repository:tag).
- `topology.links` — the wiring between nodes. Each link has two `endpoints`, written as `"<node-name>:<interface>"`. Every link creates a point-to-point virtual connection between the two interfaces.

Containerlab also ships many ready-to-run lab examples with complete topology files — see <https://containerlab.dev/lab-examples/lab-examples/>.

---

## 5. Lab lifecycle (deploy, inspect, destroy)

### Deploy a lab

From the directory that holds the topology file:

```bash
sudo containerlab deploy
```

- `deploy` automatically looks up a file matching the `*.clab.y*ml` pattern in the current directory. To pick a specific file use `-t` / `--topo`:

  ```bash
  sudo containerlab deploy -t srlceos01.clab.yml
  ```

- `deploy` is idempotent — re-running it reconciles the lab with the topology file.
- On completion containerlab prints a summary table with each node's name, container ID, image, kind, state and management IP addresses.
- To run a lab defined in a remote Git repo/HTTP URL, point `--topo` at the URL.

### List lab nodes

```bash
# nodes of the lab in the current directory
containerlab inspect

# all deployed labs
containerlab inspect -a
```

`inspect` shows the same table as deploy, incl. the management IPv4/IPv6 addresses of every node.

### Destroy a lab

Removes the containers and the lab's wiring:

```bash
sudo containerlab destroy
```

Use `-t <file>` to target a specific topology file and `--cleanup` to also delete the lab's directory.

### Other lifecycle commands

| Command | Purpose |
|---|---|
| `containerlab start` / `stop` | start/stop containers of an existing (deployed but stopped) lab |
| `containerlab restart` | restart a lab's containers |
| `containerlab redeploy` | destroy and re-deploy a lab (keeps config artifacts by default) |
| `containerlab exec -t <file> --cmd '<command>'` | run a command on all lab nodes (e.g. `--cmd 'ip -4 a show dummy-mgmt0'`); filter nodes with `--label` or node name |
| `containerlab save -t <file>` | save node configs to the lab's config directory (per-kind behavior) |
| `containerlab graph` | open a web-based topology graph |
| `containerlab version` | show version info |

> Naming convention: node containers are named `clab-<lab-name>-<node-name>`.

---

## 6. Management network

Every node is connected to a containerlab-managed **management network**:

- Default Docker network name: `clab`
- IPv4: `172.20.20.0/24`, gateway `172.20.20.1`
- IPv6: `3fff:172:20:20::/64`, gateway `3fff:172:20:20::1`

Deploying a lab also appends static DNS entries to the host's `/etc/hosts` following the pattern `clab-$labName-$nodeName`, e.g. for lab `demo` with node `l1`:

```
###### CLAB-demo-START ######
172.20.20.2     clab-demo-l1
###### CLAB-demo-END ######
```

This lets you reach nodes from the host by name. The *data* links defined in `topology.links` are separate — they wire the nodes' data-plane interfaces to each other.

---

## 7. Connecting to the nodes

Nodes are regular containers, so you can connect to them like to any other container:

```bash
# SSH to a Nokia SR Linux node's CLI (from the lab host, using the /etc/hosts entry)
ssh admin@clab-srlceos01-srl

# or exec into the container
docker exec -it clab-srlceos01-srl sr_cli   # SR Linux CLI
docker exec -it clab-srlceos01-srl bash     # SR Linux shell
docker exec -it clab-srlceos01-ceos Cli     # cEOS CLI
```

> Credentials and management interfaces differ per kind — each kind page documents them (e.g. <https://containerlab.dev/manual/kinds/srl/>). Many kinds default to an `admin` user; check the kind documentation for the password of the image you use.

---

## 8. Container images

- Image names follow Docker conventions (registry/organisation/repository:tag). If no registry is given, `docker.io` is assumed.
- On `deploy`, containerlab first checks locally available images (`docker images`) and pulls missing ones from the registry automatically.
- Some images are not publicly downloadable. For example, the Arista cEOS image requires an arista.com account; after downloading the archive, import it so it is known to Docker:

  ```bash
  # import container image and save it under ceos:4.32.0F name
  docker import cEOS64-lab-4.32.0F.tar.xz ceos:4.32.0F
  ```

---

## 9. Where to go next (official docs)

- Quickstart & lab walkthrough: <https://containerlab.dev/quickstart/>
- Topology definition reference: <https://containerlab.dev/manual/topo-def-file/>
- Node kinds catalog: <https://containerlab.dev/manual/kinds/>
- User manual (networking, multi-node, config artifacts, GUI, ...): <https://containerlab.dev/manual/topo-def-file/> and the "User manual" menu on the site
- Command reference: <https://containerlab.dev/cmd/deploy/>
- Lab examples catalog: <https://containerlab.dev/lab-examples/lab-examples/>
- Community / Discord: <https://containerlab.dev/community/>
