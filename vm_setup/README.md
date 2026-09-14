# Honeypot VM — Setup Guide

This folder contains everything needed to build the honeypot VM from a fresh Ubuntu Server 24.04 install.
Work through the sections in order. Each section tells you what to type and what to expect.

---

## Before you start

You need a fresh Ubuntu Server 24.04 VM. The guide assumes:
- Username: `vboxuser`
- Home directory: `/home/vboxuser`
- Network interface: `enp0s3`

Open a terminal on the VM (or SSH in from your Windows host at `192.168.0.3`).

---

## Part 1 — System packages

Install the tools everything else depends on:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3 python3-pip python3-venv curl unzip \
    iptables iptables-persistent netfilter-persistent
```

---

## Part 2 — Install Zeek

Zeek is the network monitor. It parses live traffic into log files the controller reads.

```bash
# Add the Zeek repository and install
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
    | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
    | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install -y zeek-6.0

# Add Zeek to PATH so you can run it by name
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
zeek --version
```

---

## Part 3 — Install Cowrie

Cowrie is the SSH/Telnet honeypot. It needs its own system user.

```bash
# Create the cowrie user (no login shell, no home login)
sudo adduser --disabled-password --gecos "" cowrie

# Clone Cowrie into that user's home directory
sudo -u cowrie git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie

# Set up Cowrie's Python environment
sudo -u cowrie bash -c "
    cd /home/cowrie/cowrie
    python3 -m venv cowrie-env
    cowrie-env/bin/pip install --upgrade pip
    cowrie-env/bin/pip install -r requirements.txt
"
```

---

## Part 4 — Install Loki

Loki is the log aggregation server. Grafana reads from it.

```bash
# Create the loki user and directories
sudo adduser --system --no-create-home --group loki
sudo mkdir -p /opt/loki/data/chunks /opt/loki/data/rules
sudo chown -R loki:loki /opt/loki

# Download Loki binary
curl -O -L https://github.com/grafana/loki/releases/download/v3.0.0/loki-linux-amd64.zip
unzip loki-linux-amd64.zip
sudo mv loki-linux-amd64 /opt/loki/loki
sudo chmod +x /opt/loki/loki
rm loki-linux-amd64.zip

# Copy the Loki config from this folder
sudo cp config/loki/loki-config.yaml /opt/loki/loki-config.yaml
```

---

## Part 5 — Install Grafana

Grafana is the dashboard you view in a browser.

```bash
sudo apt install -y apt-transport-https software-properties-common
wget -q -O - https://apt.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update
sudo apt install -y grafana

sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

---

## Part 6 — Clone the repo and set up Python

The controller and ML code live in the main repo. Clone it into `/home/vboxuser/honeypot`:

```bash
cd /home/vboxuser
git clone <repo-url> honeypot
cd honeypot

# Create the virtual environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Keep the venv activated for the remaining steps.

---

## Part 7 — Install Promtail

Promtail ships log files to Loki. Run the install script from inside the repo:

```bash
cd /home/vboxuser/honeypot/vm_setup
sudo bash 1_install/install_promtail.sh
```

This downloads the Promtail binary, puts it at `/opt/promtail/promtail`, and copies the config.

---

## Part 8 — Copy configs into place

The `config/` folder here contains the runtime configs for every service. Copy them:

```bash
cd /home/vboxuser/honeypot/vm_setup

# Cowrie
sudo cp config/cowrie/cowrie.cfg /home/cowrie/cowrie/etc/cowrie.cfg

# Loki (already done in Part 4 — skip if you did it)
# sudo cp config/loki/loki-config.yaml /opt/loki/loki-config.yaml

# Promtail (already done by install_promtail.sh — skip if you ran it)
# sudo cp config/promtail/promtail-config.yaml /opt/promtail/promtail-config.yaml

# Controller configs (allowlist, phase, port allowlist)
sudo cp config/allowlist.txt /home/vboxuser/honeypot/config/allowlist.txt
sudo cp config/phase.conf /home/vboxuser/honeypot/config/phase.conf
sudo cp config/port_allowlist.yaml /home/vboxuser/honeypot/config/port_allowlist.yaml
```

---

## Part 9 — Install systemd services

This registers all services to start automatically on boot:

```bash
cd /home/vboxuser/honeypot/vm_setup
sudo bash 1_install/install_all_services.sh
sudo bash 1_install/install_controller_service.sh
```

After this, every service is enabled. They will start on the next reboot, or you can start them manually in Part 11.

---

## Part 10 — Configure Grafana

This copies the Loki datasource and dashboard into Grafana, then restarts it:

```bash
cd /home/vboxuser/honeypot/vm_setup
sudo bash 2_configure/setup_grafana.sh
```

Open `http://<vm-ip>:3000` in your browser. Log in with `admin` / `admin` and change the password when prompted. The Loki datasource and the honeypot dashboard should already be there.

---

## Part 11 — Set up Cowrie port forwarding

This redirects external SSH (port 22) and Telnet (port 23) traffic into Cowrie's listeners.
Your own SSH session from the Windows host is excluded so you don't lock yourself out.

```bash
cd /home/vboxuser/honeypot/vm_setup
sudo bash 2_configure/setup_cowrie_portfwd.sh
```

The rules are saved to `/etc/iptables/rules.v4` and restored automatically on reboot.

---

## Part 12 — Set the operating phase

Three phases are available. Start with `static` (no adaptive behavior, just data collection):

```bash
cd /home/vboxuser/honeypot/vm_setup
sudo bash 2_configure/set_phase.sh static
```

You can switch later without restarting the controller:

```bash
sudo bash 2_configure/set_phase.sh adaptive       # enables port rotation
sudo bash 2_configure/set_phase.sh adaptive_ml    # adds ML scoring (shadow mode by default)
```

---

## Part 13 — Start everything

```bash
cd /home/vboxuser/honeypot/vm_setup

sudo bash 4_operate/start_loki.sh
sudo bash 4_operate/start_promtail.sh
sudo bash 4_operate/start_cowrie.sh
sudo bash 4_operate/start_controller.sh
```

Check that each one is running:

```bash
sudo systemctl status loki promtail cowrie zeek honeypot-controller
```

All five should show `active (running)`.

---

## Checking logs

| What to check | Command |
|---|---|
| Controller activity | `sudo tail -f /var/log/honeypot/controller.log` |
| Controller via systemd | `sudo journalctl -u honeypot-controller -f` |
| Cowrie sessions | `sudo tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| Loki | `sudo journalctl -u loki -f` |
| Zeek | `ls /opt/zeek/logs/current/` |

---

## Stopping services

```bash
cd /home/vboxuser/honeypot/vm_setup
sudo bash 4_operate/stop_controller.sh
sudo bash 4_operate/stop_cowrie.sh
```

Or stop everything at once:

```bash
sudo systemctl stop honeypot-controller cowrie loki promtail zeek
```

---

## Safety rules

1. IP `192.168.0.3` (your Windows host) is in `config/allowlist.txt` and will never be auto-blocked.
2. The controller runs in shadow mode by default — it logs what *would* be blocked but does not actually drop traffic. Verify shadow mode is working before enabling live blocking.
3. The egress lockdown script (`2_configure/apply_egress_lockdown.sh`) cuts off outbound internet. **Do not run this during setup** — you still need internet access for installs. Only run it when the honeypot goes live on the target network.
4. Any firewall rule changes require your manual approval.
