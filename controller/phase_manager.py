"""Phase management: reads phase.conf and enforces port exposure rules."""
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

PHASE_CONF = Path(__file__).parent.parent / "config" / "phase.conf"
PORT_ALLOWLIST = Path(__file__).parent.parent / "config" / "port_allowlist.yaml"

VALID_PHASES = {"static", "adaptive", "adaptive_ml"}


def read_phase(path: Path = PHASE_CONF) -> str:
    """Return the active phase name from phase.conf."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            key, _, value = line.partition("=")
            if key.strip() == "phase":
                phase = value.strip()
                if phase not in VALID_PHASES:
                    raise ValueError(f"Unknown phase '{phase}'. Must be one of {VALID_PHASES}")
                return phase
    raise ValueError(f"No 'phase' key found in {path}")


def load_port_allowlist(path: Path = PORT_ALLOWLIST) -> list[dict]:
    """Return the full port allow-list from port_allowlist.yaml."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("ports", [])


def ports_for_phase(phase: str, path: Path = PORT_ALLOWLIST) -> list[dict]:
    """Return only the ports permitted for the given phase."""
    return [
        p for p in load_port_allowlist(path)
        if phase in p.get("phases", [])
    ]
