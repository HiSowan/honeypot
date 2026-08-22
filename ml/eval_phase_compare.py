"""Phase 1 vs Phase 2 port-exposure experiment.

Demonstrates the adaptive rotation mechanism by:
1. Applying Phase 1 iptables rules (all allow-list ports ACCEPT)
2. Simulating what the controller does when it detects a scanner
3. Comparing the port sets before and after rotation

Uses an isolated iptables chain (HONEYPOT_EXP) so existing rules are untouched.

Usage (run as root or with sudo, from ~/honeypot with venv active):

  Step 1 — set up Phase 1:
      sudo python ml/eval_phase_compare.py --setup-phase1

  [Run nmap from Kali — see kali_scan.sh]

  Step 2 — simulate Phase 2 rotation (controller detected scan of ports 22,80):
      sudo python ml/eval_phase_compare.py --rotate --probed 22,80

  [Run nmap from Kali again]

  Step 3 — print comparison report:
      sudo python ml/eval_phase_compare.py --report

  Cleanup:
      sudo python ml/eval_phase_compare.py --cleanup
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

# ── Allow-list (Phase 1 static ports, from CLAUDE.md) ────────────────────
PHASE1_PORTS = [21, 22, 23, 25, 80, 443, 445]
EXP_CHAIN    = "HONEYPOT_EXP"
SNAPSHOT_DIR = Path("/tmp/honeypot_exp")

# ── iptables helpers ──────────────────────────────────────────────────────

def run_ipt(*args, check=True):
    cmd = ["iptables"] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        # Ignore "already exists" / "not found" errors
        if "already exists" in r.stderr or "No chain" in r.stderr:
            return r
        print(f"  iptables warning: {r.stderr.strip()}", file=sys.stderr)
    return r


def ensure_chain():
    run_ipt("-N", EXP_CHAIN, check=False)
    # Hook into INPUT only once
    r = subprocess.run(["iptables", "-C", "INPUT", "-j", EXP_CHAIN],
                       capture_output=True)
    if r.returncode != 0:
        run_ipt("-I", "INPUT", "1", "-j", EXP_CHAIN)


def flush_chain():
    run_ipt("-F", EXP_CHAIN, check=False)


def remove_chain():
    flush_chain()
    run_ipt("-D", "INPUT", "-j", EXP_CHAIN, check=False)
    run_ipt("-X", EXP_CHAIN, check=False)


def open_port(port):
    run_ipt("-A", EXP_CHAIN, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")


def drop_port(port):
    run_ipt("-A", EXP_CHAIN, "-p", "tcp", "--dport", str(port), "-j", "DROP")


def snapshot_state(label):
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    r = subprocess.run(
        ["iptables", "-L", EXP_CHAIN, "-n", "--line-numbers"],
        capture_output=True, text=True
    )
    path = SNAPSHOT_DIR / f"{label}.txt"
    path.write_text(r.stdout)
    return r.stdout


def parse_ports_from_snapshot(text):
    """Return {port: verdict} from iptables -L output."""
    result = {}
    for line in text.splitlines():
        if "tcp dpt:" in line:
            verdict = line.split()[0]   # ACCEPT or DROP
            port_part = [t for t in line.split() if t.startswith("dpt:")]
            if port_part:
                port = int(port_part[0].split(":")[1])
                result[port] = verdict
    return result


# ── Commands ──────────────────────────────────────────────────────────────

def cmd_setup_phase1():
    print("=== PHASE 1 SETUP — all allow-list ports ACCEPT ===")
    ensure_chain()
    flush_chain()
    for port in PHASE1_PORTS:
        open_port(port)
        print(f"  ACCEPT port {port}/tcp")
    state = snapshot_state("phase1")
    print()
    print(state)
    print(f"Snapshot saved to {SNAPSHOT_DIR}/phase1.txt")
    print()
    print("Now run from Kali:  bash ml/kali_scan.sh scan1")


def cmd_rotate(probed_str):
    probed = set(int(p) for p in probed_str.split(","))
    print(f"=== PHASE 2 ROTATION — scanner probed ports: {sorted(probed)} ===")
    ensure_chain()
    flush_chain()
    for port in PHASE1_PORTS:
        if port in probed:
            drop_port(port)
            print(f"  DROP  port {port}/tcp  (already probed — hiding from attacker)")
        else:
            open_port(port)
            print(f"  ACCEPT port {port}/tcp  (unprobed — keeping visible)")
    state = snapshot_state("phase2")
    print()
    print(state)
    print(f"Snapshot saved to {SNAPSHOT_DIR}/phase2.txt")
    print()
    print("Now run from Kali:  bash ml/kali_scan.sh scan2")


def cmd_report():
    p1_file = SNAPSHOT_DIR / "phase1.txt"
    p2_file = SNAPSHOT_DIR / "phase2.txt"
    if not p1_file.exists() or not p2_file.exists():
        print("ERROR: run --setup-phase1 and --rotate first.")
        sys.exit(1)

    p1 = parse_ports_from_snapshot(p1_file.read_text())
    p2 = parse_ports_from_snapshot(p2_file.read_text())

    print()
    print("=" * 65)
    print("PHASE COMPARISON REPORT")
    print("=" * 65)
    print()
    print(f"{'Port':<8} {'Phase 1':^12} {'Phase 2':^12} {'Change'}")
    print("-" * 48)

    all_ports = sorted(set(p1) | set(p2))
    hidden, revealed, stable = [], [], []
    for port in all_ports:
        v1 = p1.get(port, "—")
        v2 = p2.get(port, "—")
        if v1 == "ACCEPT" and v2 == "DROP":
            change = "HIDDEN (probed → rotated away)"
            hidden.append(port)
        elif v1 == "DROP" and v2 == "ACCEPT":
            change = "REVEALED"
            revealed.append(port)
        elif v1 == v2:
            change = "unchanged"
            stable.append(port)
        else:
            change = f"{v1} → {v2}"
        print(f"{port:<8} {v1:^12} {v2:^12} {change}")

    print()
    print("=" * 65)
    print("SUMMARY")
    print("=" * 65)
    print(f"Ports visible in Phase 1 : {sorted(p for p,v in p1.items() if v=='ACCEPT')}")
    print(f"Ports visible in Phase 2 : {sorted(p for p,v in p2.items() if v=='ACCEPT')}")
    print(f"Ports hidden after rotation : {hidden}  (DROP — scanner probed these)")
    print(f"Ports newly visible after rotation : {revealed}")
    print()
    overlap = set(p for p,v in p1.items() if v=='ACCEPT') & \
              set(p for p,v in p2.items() if v=='ACCEPT')
    p1_acc  = set(p for p,v in p1.items() if v=='ACCEPT')
    p2_acc  = set(p for p,v in p2.items() if v=='ACCEPT')
    pct = 100*len(overlap)/len(p1_acc) if p1_acc else 0
    print(f"Port-set overlap (Phase1 ∩ Phase2) / Phase1 : "
          f"{len(overlap)}/{len(p1_acc)} = {pct:.0f}%")
    print()
    print("INTERPRETATION")
    print("-" * 48)
    print(f"An attacker who scanned Phase 1 and found {sorted(p1_acc)}")
    print(f"will find {sorted(p2_acc)} on the next scan after rotation.")
    print(f"{len(hidden)} port(s) that were scanned are now hidden.")
    if revealed:
        print(f"{len(revealed)} port(s) that were not yet scanned are now exposed —")
        print("  attacker must probe again to find them, generating more log data.")
    print()
    print("Moving-target effect: port set is unpredictable across scans.")
    print("Attack surface enumeration requires repeated reconnaissance → "
          "more Zeek log entries → higher detection probability.")

    # Save report
    report_path = SNAPSHOT_DIR / "phase_comparison_report.txt"
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_report_inner(p1, p2, hidden, revealed, overlap, p1_acc, p2_acc)
    report_path.write_text(buf.getvalue())
    print(f"\nReport saved to {report_path}")


def cmd_report_inner(p1, p2, hidden, revealed, overlap, p1_acc, p2_acc):
    all_ports = sorted(set(p1) | set(p2))
    print("Phase 1 vs Phase 2 Port Exposure Comparison")
    print()
    for port in all_ports:
        v1 = p1.get(port, "—"); v2 = p2.get(port, "—")
        print(f"  Port {port}: {v1} → {v2}")
    print()
    pct = 100*len(overlap)/len(p1_acc) if p1_acc else 0
    print(f"Phase 1 visible: {sorted(p1_acc)}")
    print(f"Phase 2 visible: {sorted(p2_acc)}")
    print(f"Overlap: {len(overlap)}/{len(p1_acc)} = {pct:.0f}%")
    print(f"Hidden: {hidden}")
    print(f"Revealed: {revealed}")


def cmd_cleanup():
    remove_chain()
    print("HONEYPOT_EXP chain removed — iptables restored to pre-experiment state.")


# ── Entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Phase 1 vs Phase 2 port exposure experiment")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--setup-phase1",  action="store_true",
                   help="Apply Phase 1 iptables rules (all ports ACCEPT)")
    g.add_argument("--rotate",        action="store_true",
                   help="Simulate rotation after scanner detected")
    g.add_argument("--report",        action="store_true",
                   help="Print comparison report from saved snapshots")
    g.add_argument("--cleanup",       action="store_true",
                   help="Remove experiment chain and restore iptables")
    p.add_argument("--probed", default="22,80",
                   help="Comma-separated ports the scanner probed (used with --rotate)")
    args = p.parse_args()

    if args.setup_phase1:
        cmd_setup_phase1()
    elif args.rotate:
        cmd_rotate(args.probed)
    elif args.report:
        cmd_report()
    elif args.cleanup:
        cmd_cleanup()
