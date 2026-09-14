# VM Setup — Adaptive Honeypot System

Complete setup guide for the Ubuntu Server 24.04 VM.
Run every step in order on the VM as a user with `sudo` rights.

---

## Prerequisites

- Ubuntu Server 24.04 fresh install
- VirtualBox host-only or NAT network configured
- Python 3.12+, git, pip installed
- Zeek 8.2 installed at `/opt/zeek/`
- Cowrie cloned to `/home/cowrie/cowrie/`

Clone the repo and activate the venv before running any script:

```bash
cd ~/honeypot
git clone <repo-url> .
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1 — Install services (`1_install/`)

Run once after cloning. Installs and enables all system services.

| Script | What it does |
|--------|--------------|
| `install_all_services.sh` | Installs Zeek, Loki, Promtail, Cowrie, and the controller in one pass |
| `install_controller_service.sh` | Registers the Python controller as a systemd service |
| `install_promtail.sh` | Installs Promtail log shipper |
| `enable_ssh_password.sh` | Enables SSH password auth on the VM (needed for benign-client test traffic) |

```bash
bash 1_install/install_all_services.sh
bash 1_install/install_controller_service.sh
bash 1_install/install_promtail.sh
```

---

## Step 2 — Configure services (`2_configure/`)

Run after installation. Order matters.

| Script | What it does |
|--------|--------------|
| `setup_cowrie_portfwd.sh` | Adds iptables PREROUTING rules to redirect port 22/23 → Cowrie listeners |
| `setup_grafana.sh` | Configures Grafana datasource (Loki) and dashboard provider |
| `set_phase.sh` | Sets the active phase (`static` / `adaptive` / `adaptive_ml`) |
| `apply_egress_lockdown.sh` | **Deploy-time only** — applies default-deny outbound rules; do NOT run during development |

```bash
bash 2_configure/setup_cowrie_portfwd.sh
bash 2_configure/setup_grafana.sh
bash 2_configure/set_phase.sh adaptive   # or: static / adaptive_ml
```

> `apply_egress_lockdown.sh` is for production deployment only. Internet must stay open during development.

---

## Step 3 — Install systemd units (`3_services/`)

Copy unit files into place and reload systemd:

```bash
sudo cp 3_services/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cowrie honeypot-controller loki promtail zeek
```

---

## Step 4 — Start / stop services (`4_operate/`)

| Script | What it does |
|--------|--------------|
| `start_controller.sh` | Starts the Python adaptive controller |
| `stop_controller.sh` | Stops the controller |
| `start_cowrie.sh` | Starts the Cowrie SSH/Telnet honeypot |
| `stop_cowrie.sh` | Stops Cowrie |
| `start_loki.sh` | Starts the Loki log aggregator |
| `start_promtail.sh` | Starts Promtail (ships logs to Loki) |

```bash
bash 4_operate/start_cowrie.sh
bash 4_operate/start_loki.sh
bash 4_operate/start_promtail.sh
bash 4_operate/start_controller.sh
```

---

## Config files (`config/`)

Copy these into the repo's `config/` directory before starting services.

| File | Purpose |
|------|---------|
| `config/allowlist.txt` | Operator IPs that must never be auto-blocked (includes 192.168.0.3) |
| `config/phase.conf` | Active phase (`static` / `adaptive` / `adaptive_ml`) |
| `config/port_allowlist.yaml` | Ports the controller may open/close |
| `config/cowrie/cowrie.cfg` | Cowrie honeypot configuration |
| `config/loki/loki-config.yaml` | Loki server configuration |
| `config/promtail/promtail-config.yaml` | Promtail scrape config (points at Zeek + Cowrie logs) |
| `config/grafana/provisioning/datasources/loki.yaml` | Grafana datasource (Loki at localhost:3100) |
| `config/grafana/provisioning/dashboards/provider.yaml` | Grafana dashboard provider path |

---

## Grafana

Grafana runs as a system service on port **3000**.
Access at `http://<vm-ip>:3000` (default credentials: admin / admin — change on first login).

The Loki datasource and dashboard provider are pre-configured in `config/grafana/`.
Dashboards are loaded from `/var/lib/grafana/dashboards/` on the VM.

---

## Operator safety rules

1. IP `192.168.0.3` (Windows host) must never be auto-blocked — it is in `config/allowlist.txt`.
2. Shadow mode must be confirmed working before enabling live ML blocking (`adaptive_ml` phase).
3. Egress lockdown (`apply_egress_lockdown.sh`) is deploy-time only — do not run during development.
4. All firewall rule changes require manual approval before execution.
