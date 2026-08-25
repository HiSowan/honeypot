"""iptables wrapper for port exposure and IP blocking.

All mutating methods are no-ops in dry_run mode — they log what would happen
instead of touching the real firewall. Always call with dry_run=True during
development and testing.

SAFETY: the operator allow-list is enforced in the controller layer before
calling block_ip(). This module does not re-check it — keep that check upstream.
"""
import logging
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# iptables chain used for all honeypot-managed block rules
_BLOCK_CHAIN = "HONEYPOT_BLOCK"


@dataclass
class Firewall:
    dry_run: bool = True
    _blocked_ips: set = field(default_factory=set, init=False)

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

    def open_port(self, port: int, protocol: str = "tcp") -> None:
        """Accept inbound traffic on port/protocol."""
        args = ["INPUT", "-p", protocol, "--dport", str(port), "-j", "ACCEPT"]
        if not self.dry_run and self._rule_exists(args):
            logger.debug("port %d/%s already open", port, protocol)
            return
        self._run(["-I"] + args)
        logger.info("opened port %d/%s", port, protocol)

    def close_port(self, port: int, protocol: str = "tcp") -> None:
        """Drop inbound traffic on port/protocol."""
        args = ["INPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"]
        if not self.dry_run and not self._rule_exists(args):
            logger.debug("port %d/%s already closed", port, protocol)
            return
        self._run(["-I"] + args)
        logger.info("closed port %d/%s", port, protocol)

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

    def add_prerouting_redirect(self, ext_port: int, int_port: int,
                                proto: str = "tcp") -> None:
        """Insert a nat/PREROUTING REDIRECT rule: packets arriving on ext_port
        are transparently redirected to the local Cowrie listener at int_port.

        This must be called BEFORE any INPUT rules so that Cowrie-managed ports
        can be rotated independently of the INPUT chain.
        """
        args = ["-t", "nat", "-I", "PREROUTING",
                "-p", proto, "--dport", str(ext_port),
                "-j", "REDIRECT", "--to-port", str(int_port)]
        self._run(args)
        logger.info("PREROUTING: :%d → Cowrie :%d added", ext_port, int_port)

    def del_prerouting_redirect(self, ext_port: int, int_port: int,
                                proto: str = "tcp") -> None:
        """Delete the nat/PREROUTING REDIRECT rule for ext_port → int_port."""
        args = ["-t", "nat", "-D", "PREROUTING",
                "-p", proto, "--dport", str(ext_port),
                "-j", "REDIRECT", "--to-port", str(int_port)]
        self._run(args)
        logger.info("PREROUTING: :%d → Cowrie :%d removed", ext_port, int_port)
