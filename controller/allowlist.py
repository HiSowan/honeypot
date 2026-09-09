import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path(__file__).parent.parent / "config" / "allowlist.txt"


def load_allowlist(path: Path = _DEFAULT_PATH) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            networks.append(ipaddress.ip_network(line, strict=False))
    return networks


def is_allowlisted(ip: str, networks: list | None = None) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        logger.debug("Ignoring unparseable address in allow-list check: %r", ip)
        return False
    if networks is None:
        networks = load_allowlist()
    return any(addr in net for net in networks)
