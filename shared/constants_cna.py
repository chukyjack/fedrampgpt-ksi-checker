"""Locked constants for FedRAMP KSI-CNA evaluations."""

# Schema version - pinned to 1.0 per spec
SCHEMA_VERSION = "1.0"

# --- KSI-CNA-01: Restrict Network Traffic ---

CNA01_KSI_ID = "KSI-CNA-01"

CNA01_KSI_NAME = "Restrict Network Traffic"

CNA01_REQUIREMENT_TEXT = (
    "KSI-CNA-01: Restrict Network Traffic. "
    "Persistently ensure all machine-based information resources are configured "
    "to limit inbound and outbound network traffic."
)

CNA01_RELATED_CONTROLS = ["AC-17.3", "CA-9", "CM-7.1", "SC-7.5", "SI-8"]

CNA01_APPLIES_TO = ["Low", "Moderate"]

# Sensitive ports that should not be exposed to 0.0.0.0/0
# Maps port number to service name for reporting
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    11211: "Memcached",
    2379: "etcd",
    2380: "etcd",
}

# Criteria definitions for CNA-01
CNA01_CRITERIA_DEFINITIONS = {
    "CNA01-A": {
        "id": "CNA01-A",
        "name": "Ingress Restrictions",
        "description": "No unrestricted inbound access on sensitive ports (SSH, RDP, database ports, etc.)",
        "requirement": "required",
        "pass_reason": "No sensitive ports are exposed to unrestricted internet access (0.0.0.0/0).",
        "fail_reason": "One or more sensitive ports are exposed to unrestricted internet access (0.0.0.0/0).",
    },
    "CNA01-B": {
        "id": "CNA01-B",
        "name": "Explicit Ingress Rules",
        "description": "All security groups have explicitly defined ingress rules.",
        "requirement": "required",
        "pass_reason": "All security groups have at least one explicitly defined ingress rule.",
        "fail_reason": "One or more security groups have no ingress rules defined.",
    },
    "CNA01-C": {
        "id": "CNA01-C",
        "name": "Egress Restrictions",
        "description": "Outbound traffic is explicitly limited (no unrestricted egress to 0.0.0.0/0 on all ports).",
        "requirement": "required",
        "pass_reason": "All security groups have restricted egress (port-limited, CIDR-limited, or SG-referenced).",
        "fail_reason": "One or more security groups have unrestricted egress (0.0.0.0/0 on all ports).",
    },
    "CNA01-D": {
        "id": "CNA01-D",
        "name": "Persistent Evaluation",
        "description": "Evaluation is triggered by scheduled automation.",
        "requirement": "required",
        "pass_reason": "Workflow triggered by scheduled event, confirming persistent evaluation cycle.",
        "fail_reason": "Workflow not triggered by schedule. Persistent evaluation cycle not demonstrated.",
    },
}

# Evidence artifact naming
CNA01_ARTIFACT_PREFIX = "evidence_ksi-cna-01"

# Check Run naming
CNA01_CHECK_RUN_NAME = "KSI-CNA-01 — Restrict Network Traffic"
CNA01_CHECK_RUN_TITLE = "FedRAMP 20x KSI Evidence: KSI-CNA-01 Restrict Network Traffic"

# --- Common Network Constants ---

# CIDR blocks that indicate unrestricted access
UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}

# Protocol value that means "all protocols"
ALL_PROTOCOLS = {"-1", "all"}

# Directories to exclude when scanning
EXCLUDED_DIRS = {
    ".terraform",
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
}
