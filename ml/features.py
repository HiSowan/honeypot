"""Feature definitions shared between training and inference.

These are the Zeek conn.log fields that overlap with UNSW-NB15,
allowing models trained on UNSW-NB15 to run on live Zeek data.
"""

# Features used by both RF and Isolation Forest
FEATURE_COLS = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "conn_state_S0",   # SYN, no reply
    "conn_state_SF",   # normal close
    "conn_state_REJ",  # rejected
    "conn_state_RSTO", # reset by originator
]

# UNSW-NB15 column mappings → our feature names
UNSW_COL_MAP = {
    "dur":      "duration",
    "sbytes":   "orig_bytes",
    "dbytes":   "resp_bytes",
    "spkts":    "orig_pkts",
    "dpkts":    "resp_pkts",
    "proto":    "proto",
    "state":    "conn_state",
}

# UNSW-NB15 attack category label column
UNSW_LABEL_COL = "attack_cat"

ATTACK_CATEGORIES = [
    "Normal",
    "Fuzzers",
    "Analysis",
    "Backdoors",
    "DoS",
    "Exploits",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
]
