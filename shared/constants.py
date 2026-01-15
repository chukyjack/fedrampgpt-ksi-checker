"""Locked constants for FedRAMP KSI-MLA-05 evaluation."""

# KSI identifier - fixed for this implementation
KSI_ID = "KSI-MLA-05"

# Schema version - pinned to 1.0 per spec
SCHEMA_VERSION = "1.0"

# FedRAMP requirement text - verbatim from specification
KSI_REQUIREMENT_TEXT = (
    "KSI-MLA-05: Evaluate Configuration. "
    "The service provider must implement machine-based evaluation of configuration "
    "as part of a persistent cycle to identify and remediate misconfigurations."
)

# Criteria definitions with locked descriptions
CRITERIA_DEFINITIONS = {
    "MLA05-A": {
        "id": "MLA05-A",
        "name": "Configuration Surface in Scope",
        "description": "Terraform configuration surface detected and in scope for evaluation.",
        "pass_reason": "Terraform configuration files detected in repository.",
        "fail_reason": "No Terraform configuration files detected in repository.",
    },
    "MLA05-B": {
        "id": "MLA05-B",
        "name": "Machine-Based Evaluation Performed",
        "description": "Machine-based evaluation of Terraform configuration completed successfully.",
        "pass_reason": "Terraform init and validate completed successfully.",
        "fail_reason": "Terraform validation failed.",
        "error_reason": "Terraform evaluation could not be completed due to tooling error.",
    },
    "MLA05-C": {
        "id": "MLA05-C",
        "name": "Persistent Cycle Configured",
        "description": "Evaluation is configured to run as part of a persistent (scheduled) cycle.",
        "pass_reason": "Workflow triggered by scheduled event, confirming persistent cycle.",
        "fail_reason": "Workflow not triggered by schedule. Persistent cycle not demonstrated.",
    },
    "MLA05-D": {
        "id": "MLA05-D",
        "name": "Evidence Artifacts Generated",
        "description": "Required evidence artifacts have been generated and are available.",
        "pass_reason": "Evidence pack generated with all required files.",
        "fail_reason": "Evidence pack could not be generated or is incomplete.",
        "error_reason": "Evidence generation failed due to an internal error.",
    },
}

# Directories to exclude when scanning for Terraform files
EXCLUDED_DIRS = {
    ".terraform",
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
}

# File patterns for Terraform detection
TF_FILE_PATTERN = "*.tf"
TF_LOCKFILE_NAME = ".terraform.lock.hcl"

# Evidence artifact naming
ARTIFACT_PREFIX = "evidence_ksi-mla-05"

# Check Run naming
CHECK_RUN_NAME = "KSI-MLA-05 — Evaluate Configuration"
CHECK_RUN_TITLE = "FedRAMP 20x KSI Evidence: KSI-MLA-05 Evaluate Configuration"
