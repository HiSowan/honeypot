"""iptables wrapper for port exposure and IP blocking.

All mutating methods are no-ops in dry_run mode — they log what would happen
instead of touching the real firewall. Always call with dry_run=True during
development and testing.

SAFETY: the operator allow-list is enforced in the controller layer before
calling block_ip(). This module does not re-check it — keep that check upstream.
"""
import logging
import shlex
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# iptables chain used for all honeypot-managed block rules
_BLOCK_CHAIN = "HONEYPOT_BLOCK"


@dataclass
class Firewall:
    dry_run: bool = True
    _blocked_ips: set = field(default_factory=set, init=False)
    _port_policies: dict[tuple[int, str], str] = field(default_factory=dict, init=False)
    _redirects: set[tuple[int, int, str]] = field(default_factory=set, init=False)
    _redirect_templates: dict[tuple[int, str], list[list[str]]] = field(default_factory=dict, init=False)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, args: list[str]) -> None:
        cmd = ["sudo", "iptables"] + args
        if self.dry_run:
            logger.info("[DRY-RUN] would run: %s", " ".join(cmd))
            return
        logger.debug("running: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("iptables error: %s", result.stderr.strip())
            raise RuntimeError(f"iptables failed: {result.stderr.strip()}")

    def _rule_exists(self, args: list[str]) -> bool:
        """Return True if the iptables rule described by args already exists."""
        check_args = ["sudo", "iptables", "-C"] + args
        result = subprocess.run(check_args, capture_output=True)
        return result.returncode == 0

    # ------------------------------------------------------------------
    # Chain lifecycle
    # ------------------------------------------------------------------

    def ensure_chain(self) -> None:
        """Create the HONEYPOT_BLOCK chain and hook it into INPUT if not present."""
        if self.dry_run:
            logger.info("[DRY-RUN] would ensure chain %s exists", _BLOCK_CHAIN)
            return
        # Create chain (ignore error if it already exists)
        subprocess.run(["sudo", "iptables", "-N", _BLOCK_CHAIN], capture_output=True)
        # Hook into INPUT if not already
        if not self._rule_exists(["INPUT", "-j", _BLOCK_CHAIN]):
            self._run(["INPUT", "-j", _BLOCK_CHAIN])

    def flush_chain(self) -> None:
        """Remove all rules from the HONEYPOT_BLOCK chain."""
        self._run(["-F", _BLOCK_CHAIN])
        self._blocked_ips.clear()

    # ------------------------------------------------------------------
    # Port management
    # ------------------------------------------------------------------

    def _list_rules(self, chain: str, table: str = "filter") -> list[list[str]]:
        """Read a snapshot; inspection failures must never mean 'rule absent'."""
        if self.dry_run:
            return []
        cmd = ["sudo", "iptables", "-t", table, "-S", chain]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"iptables inspection failed: {result.stderr.strip()}")
        rules = [shlex.split(line) for line in result.stdout.splitlines()]
        return [r[2:] for r in rules if r[:2] == ["-A", chain]]

    @staticmethod
    def _normalise_rule(rule: list[str]) -> list[str]:
        # iptables -S inserts '-m tcp/udp' and spells --to-port as --to-ports.
        # Keep all other qualifiers, so source/interface-specific rules cannot
        # be mistaken for this controller's unconditional rules.
        result = []
        i = 0
        while i < len(rule):
            if rule[i:i + 2] in (["-m", "tcp"], ["-m", "udp"]):
                i += 2
                continue
            result.append("--to-ports" if rule[i] == "--to-port" else rule[i])
            i += 1
        return result

    def _delete_listed_rule(self, chain: str, rule: list[str], table: str = "filter") -> None:
        try:
            self._run(["-t", table, "-D", chain, *rule])
        except RuntimeError:
            # Another writer may have removed it since the snapshot. A failed
            # inspection or a still-present rule remains a real error.
            if rule in self._list_rules(chain, table):
                raise

    def _set_port_policy(self, port: int, protocol: str, verdict: str) -> None:
        key = (port, protocol)
        desired = ["-p", protocol, "--dport", str(port), "-j", verdict]
        if self.dry_run:
            if self._port_policies.get(key) != verdict:
                self._run(["-I", "INPUT", *desired])
        else:
            matches = []
            for rule in self._list_rules("INPUT"):
                normal = self._normalise_rule(rule)
                if normal[:-1] == desired[:-1] and normal[-1:] in (["ACCEPT"], ["DROP"]):
                    matches.append((rule, normal[-1]))
            keep = next((i for i, (_, action) in enumerate(matches) if action == verdict), None)
            if keep is None:
                self._run(["-I", "INPUT", *desired])
            for i, (rule, _) in enumerate(matches):
                if i != keep:
                    self._delete_listed_rule("INPUT", rule)
        self._port_policies[key] = verdict
        logger.debug("port %d/%s policy %s", port, protocol, verdict)

    def port_policies(self) -> dict[tuple[int, str], str]:
        """Return a copy of successfully requested policies (also in dry-run)."""
        return dict(self._port_policies)

    def open_port(self, port: int, protocol: str = "tcp") -> None:
        """Keep one ACCEPT rule and remove conflicting unconditional DROP rules."""
        self._set_port_policy(port, protocol, "ACCEPT")

    def close_port(self, port: int, protocol: str = "tcp") -> None:
        """Keep one DROP rule and remove conflicting unconditional ACCEPT rules."""
        self._set_port_policy(port, protocol, "DROP")

    # ------------------------------------------------------------------
    # IP blocking (Phase 3 — ML-driven)
    # ------------------------------------------------------------------

    def block_ip(self, ip: str) -> None:
        """Drop all inbound traffic from ip."""
        if ip in self._blocked_ips:
            logger.debug("%s already blocked", ip)
            return
        self._run(["-I", _BLOCK_CHAIN, "-s", ip, "-j", "DROP"])
        self._blocked_ips.add(ip)
        logger.info("blocked IP %s", ip)

    def unblock_ip(self, ip: str) -> None:
        """Remove block rule for ip."""
        if ip not in self._blocked_ips:
            logger.debug("%s not in blocked set", ip)
            return
        self._run(["-D", _BLOCK_CHAIN, "-s", ip, "-j", "DROP"])
        self._blocked_ips.discard(ip)
        logger.info("unblocked IP %s", ip)

    def blocked_ips(self) -> frozenset[str]:
        return frozenset(self._blocked_ips)

    # ------------------------------------------------------------------
    # PREROUTING DNAT/REDIRECT (Cowrie port rotation — Phase 2/3)
    # ------------------------------------------------------------------

    def _redirect_rules(self, int_port: int, proto: str,
                        include_qualified: bool = False) -> list[tuple[list[str], int]]:
        matches = []
        for rule in self._list_rules("PREROUTING", "nat"):
            normal = self._normalise_rule(rule)
            if include_qualified:
                if "--to-ports" not in normal or "-j" not in normal:
                    continue
                if (normal[normal.index("--to-ports") + 1] != str(int_port)
                        or normal[normal.index("-j") + 1] != "REDIRECT"):
                    continue
                if "-p" not in normal or normal[normal.index("-p") + 1] != proto:
                    continue
                if "--dport" not in normal:
                    raise RuntimeError(f"Unsupported Cowrie redirect: {rule}")
                index = normal.index("--dport")
                if index > 0 and normal[index - 1] == "!":
                    raise RuntimeError(f"Negated Cowrie destination port: {rule}")
                port_text = normal[index + 1]
            else:
                if not (len(normal) == 8 and normal[:3] == ["-p", proto, "--dport"]
                        and normal[4:] == ["-j", "REDIRECT", "--to-ports", str(int_port)]):
                    continue
                port_text = normal[3]
            try:
                ext_port = int(port_text)
            except ValueError:
                if include_qualified:
                    raise RuntimeError(f"Unsupported Cowrie port range: {rule}") from None
                continue
            matches.append((rule, ext_port))
        return matches

    def current_redirect_port(self, int_port: int, default: int, proto: str = "tcp") -> int:
        """Recover the port and retain every source/interface restriction.

        Dry-run uses only simulated in-memory rules; returning the default does
        not claim that a kernel rule exists. It never reads the real firewall.
        Multiple rules for the same port (e.g. NAT and lab interfaces) are
        expected. Multiple distinct ports are ambiguous and need reconciliation
        by the operator; never silently broaden a restricted rule to all traffic.
        """
        if self.dry_run:
            ports = {ext for ext, target, p in self._redirects if (target, p) == (int_port, proto)}
        else:
            matches = self._redirect_rules(int_port, proto, include_qualified=True)
            ports = {ext for _, ext in matches}
            if len(ports) <= 1:
                self._redirect_templates[(int_port, proto)] = [rule for rule, _ in matches]
        if len(ports) > 1:
            raise RuntimeError(f"Multiple Cowrie redirects to {int_port}/{proto}: {sorted(ports)}")
        return next(iter(ports), default)

    def _redirect_specs(self, ext_port: int, int_port: int, proto: str) -> list[list[str]]:
        templates = self._redirect_templates.get((int_port, proto))
        if not templates:
            return [["-p", proto, "--dport", str(ext_port), "-j", "REDIRECT", "--to-ports", str(int_port)]]
        specs = []
        for template in templates:
            spec = list(template)
            spec[spec.index("--dport") + 1] = str(ext_port)
            if spec not in specs:
                specs.append(spec)
        return specs

    def add_prerouting_redirect(self, ext_port: int, int_port: int,
                                proto: str = "tcp") -> None:
        """Ensure one copy of each recovered rule, changing only its port."""
        key = (ext_port, int_port, proto)
        if self.dry_run and key in self._redirects:
            return
        rules = self._list_rules("PREROUTING", "nat")
        for spec in self._redirect_specs(ext_port, int_port, proto):
            matches = [rule for rule in rules if self._normalise_rule(rule) == self._normalise_rule(spec)]
            if not matches:
                self._run(["-t", "nat", "-I", "PREROUTING", *spec])
            for rule in matches[1:]:
                self._delete_listed_rule("PREROUTING", rule, "nat")
        self._redirects.add(key)

    def del_prerouting_redirect(self, ext_port: int, int_port: int,
                                proto: str = "tcp") -> None:
        """Remove only recovered matching rules; absence is already success."""
        if self.dry_run and (ext_port, int_port, proto) not in self._redirects:
            return
        rules = self._list_rules("PREROUTING", "nat")
        for spec in self._redirect_specs(ext_port, int_port, proto):
            if self.dry_run:
                self._run(["-t", "nat", "-D", "PREROUTING", *spec])
            else:
                for rule in rules:
                    if self._normalise_rule(rule) == self._normalise_rule(spec):
                        self._delete_listed_rule("PREROUTING", rule, "nat")
        self._redirects.discard((ext_port, int_port, proto))
