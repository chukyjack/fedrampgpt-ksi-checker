"""Pydantic schemas for FedRAMP KSI-MLA-05 evidence artifacts.

These schemas define the exact structure of all JSON files in the evidence pack.
Schema version is pinned to 1.0 per specification.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class KSIStatus(str, Enum):
    """Overall KSI evaluation status."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class CriterionStatus(str, Enum):
    """Individual criterion evaluation status."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"


# --- Terraform Detection Schema ---


class TerraformDetection(BaseModel):
    """Schema for terraform_detection.json (v1.0)."""

    schema_version: str = "1.0"
    detected: bool = Field(description="Whether Terraform files were found")
    tf_file_count: int = Field(description="Number of .tf files found")
    tf_paths: list[str] = Field(description="Unique directories containing .tf files")
    lockfile_present: bool = Field(description="Whether .terraform.lock.hcl exists")
    scanned_at: str = Field(description="ISO 8601 timestamp of scan")


# --- Terraform Inventory Schema ---


class ResourceTypeSummary(BaseModel):
    """Summary of resources by type."""

    count: int
    files: list[str] = Field(description="Files where this resource type is declared")


class ResourceSummary(BaseModel):
    """Aggregated resource information."""

    total_count: int = 0
    by_type: dict[str, ResourceTypeSummary] = Field(default_factory=dict)


class ProviderInfo(BaseModel):
    """Provider information extracted from Terraform configuration."""

    name: str
    source: str | None = None
    version_constraint: str | None = None


class ModuleInfo(BaseModel):
    """Module information extracted from Terraform configuration."""

    name: str
    source: str
    version: str | None = None
    declared_in: str = Field(description="File where module is declared")


class TerraformInventory(BaseModel):
    """Schema for terraform_inventory.json (v1.0)."""

    schema_version: str = "1.0"
    generated_at: str = Field(description="ISO 8601 timestamp")
    terraform_paths: list[str] = Field(description="Root paths containing Terraform")
    resources: ResourceSummary = Field(default_factory=ResourceSummary)
    providers: list[ProviderInfo] = Field(default_factory=list)
    modules: list[ModuleInfo] = Field(default_factory=list)
    files_analyzed: list[str] = Field(default_factory=list)


# --- Evaluation Manifest Schema ---


class CriterionResult(BaseModel):
    """Result for a single evaluation criterion."""

    id: str = Field(description="Criterion ID (e.g., MLA05-A)")
    name: str = Field(description="Human-readable criterion name")
    status: CriterionStatus
    reason: str = Field(description="Explanation for the status")
    details: dict[str, Any] | None = Field(
        default=None, description="Additional details if applicable"
    )


class ProcessInfo(BaseModel):
    """Information about the evaluation process."""

    workflow_name: str
    workflow_run_id: str
    workflow_run_url: str
    trigger_event: str
    commit_sha: str
    repository: str
    actor: str


class ScopeInfo(BaseModel):
    """Scope of the evaluation."""

    repository: str
    commit_sha: str
    configuration_surfaces: list[str] = Field(
        default_factory=lambda: ["TERRAFORM"],
        description="Configuration surfaces in scope",
    )
    terraform_paths: list[str] = Field(
        default_factory=list, description="Paths containing Terraform configuration"
    )


class EvaluationManifest(BaseModel):
    """Schema for evaluation_manifest.json (v1.0).

    This is the primary output file that determines PASS/FAIL/ERROR status.
    """

    schema_version: str = "1.0"
    ksi_id: str = "KSI-MLA-05"
    requirement_text: str
    status: KSIStatus
    reasons: list[str] = Field(description="List of reasons for the status")
    evaluated_at: str = Field(description="ISO 8601 timestamp")
    scope: ScopeInfo
    process: ProcessInfo
    criteria: list[CriterionResult]


# --- Supporting File Schemas ---


class CollectedAt(BaseModel):
    """Schema for collected_at.json."""

    schema_version: str = "1.0"
    timestamp: str = Field(description="ISO 8601 timestamp")
    timezone: str = "UTC"


class ToolsInfo(BaseModel):
    """Schema for tools.json."""

    schema_version: str = "1.0"
    terraform_version: str | None = None
    action_version: str = "1.0.0"
    python_version: str | None = None


class FileEntry(BaseModel):
    """Entry in the manifest file list."""

    path: str
    schema_version: str | None = None
    description: str


class EvidenceManifest(BaseModel):
    """Schema for manifest.json - indexes all files in evidence pack."""

    schema_version: str = "1.0"
    ksi_id: str = "KSI-MLA-05"
    generated_at: str
    commit_sha: str
    repository: str
    files: list[FileEntry]


# --- Results Summary (for App consumption) ---


class ResultsSummary(BaseModel):
    """Schema for results.json - quick reference for the App."""

    ksi_id: str = "KSI-MLA-05"
    status: KSIStatus
    manifest_path: str = "evidence/ksi-mla-05/evaluation_manifest.json"
    artifact_name: str
    summary: str
