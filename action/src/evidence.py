"""Evidence pack generation module.

Generates the complete evidence pack artifact for KSI-MLA-05.
"""

import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.constants import ARTIFACT_PREFIX, CRITERIA_DEFINITIONS, KSI_ID, KSI_REQUIREMENT_TEXT
from shared.schemas import (
    CollectedAt,
    CriterionResult,
    CriterionStatus,
    EvaluationManifest,
    EvidenceManifest,
    FileEntry,
    KSIStatus,
    ProcessInfo,
    ResultsSummary,
    ScopeInfo,
    TerraformDetection,
    TerraformInventory,
    ToolsInfo,
)

from action.src.evaluate import TerraformEvalResult


class EvidencePackBuilder:
    """Builder for FedRAMP KSI-MLA-05 evidence pack."""

    def __init__(self, output_dir: str | Path = "."):
        """Initialize the evidence pack builder.

        Args:
            output_dir: Directory to write evidence files and zip
        """
        self.output_dir = Path(output_dir).resolve()
        self.evidence_dir = self.output_dir / "evidence" / "ksi-mla-05"
        self.declared_dir = self.evidence_dir / "declared"
        self.files_written: list[tuple[str, str]] = []  # (relative_path, description)
        self.timestamp = datetime.now(timezone.utc)

    def setup_directories(self) -> None:
        """Create evidence directory structure."""
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.declared_dir.mkdir(parents=True, exist_ok=True)

    def write_json_file(
        self,
        filename: str,
        data: dict[str, Any],
        description: str,
        subdir: str | None = None,
    ) -> Path:
        """Write a JSON file to the evidence pack.

        Args:
            filename: Name of the file
            data: Data to write as JSON
            description: Description for manifest
            subdir: Optional subdirectory (e.g., "declared")

        Returns:
            Path to written file
        """
        if subdir:
            target_dir = self.evidence_dir / subdir
            rel_path = f"evidence/ksi-mla-05/{subdir}/{filename}"
        else:
            target_dir = self.evidence_dir
            rel_path = f"evidence/ksi-mla-05/{filename}"

        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / filename

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        self.files_written.append((rel_path, description))
        return file_path

    def write_collected_at(self) -> None:
        """Write collected_at.json."""
        data = CollectedAt(
            timestamp=self.timestamp.isoformat(),
            timezone="UTC",
        )
        self.write_json_file(
            "collected_at.json",
            data.model_dump(),
            "Timestamp of evidence collection",
        )

    def write_scope(
        self,
        repository: str,
        commit_sha: str,
        tf_paths: list[str],
    ) -> None:
        """Write scope.json."""
        data = ScopeInfo(
            repository=repository,
            commit_sha=commit_sha,
            configuration_surfaces=["TERRAFORM"],
            terraform_paths=tf_paths,
        )
        self.write_json_file(
            "scope.json",
            data.model_dump(),
            "Scope of the evaluation",
        )

    def write_tools(
        self,
        terraform_version: str | None,
        action_version: str = "1.0.0",
    ) -> None:
        """Write tools.json."""
        data = ToolsInfo(
            terraform_version=terraform_version,
            action_version=action_version,
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
        self.write_json_file(
            "tools.json",
            data.model_dump(),
            "Tools and versions used for evaluation",
        )

    def write_terraform_detection(self, detection: TerraformDetection) -> None:
        """Write terraform_detection.json."""
        self.write_json_file(
            "terraform_detection.json",
            detection.model_dump(),
            "Terraform detection results",
            subdir="declared",
        )

    def write_terraform_inventory(self, inventory: TerraformInventory) -> None:
        """Write terraform_inventory.json."""
        self.write_json_file(
            "terraform_inventory.json",
            inventory.model_dump(),
            "Terraform configuration inventory",
            subdir="declared",
        )

    def compute_criteria(
        self,
        detection: TerraformDetection,
        eval_result: TerraformEvalResult | None,
        trigger_event: str,
        evidence_generated: bool,
    ) -> list[CriterionResult]:
        """Compute status for each criterion.

        Args:
            detection: Terraform detection results
            eval_result: Terraform evaluation results (None if not run)
            trigger_event: GitHub event that triggered the workflow
            evidence_generated: Whether evidence pack was generated

        Returns:
            List of CriterionResult for each criterion
        """
        criteria: list[CriterionResult] = []

        # MLA05-A: Configuration Surface in Scope
        mla05_a = CRITERIA_DEFINITIONS["MLA05-A"]
        if detection.detected:
            criteria.append(
                CriterionResult(
                    id="MLA05-A",
                    name=mla05_a["name"],
                    status=CriterionStatus.PASS,
                    reason=mla05_a["pass_reason"],
                    details={"tf_file_count": detection.tf_file_count},
                )
            )
        else:
            criteria.append(
                CriterionResult(
                    id="MLA05-A",
                    name=mla05_a["name"],
                    status=CriterionStatus.FAIL,
                    reason=mla05_a["fail_reason"],
                )
            )

        # MLA05-B: Machine-Based Evaluation Performed
        mla05_b = CRITERIA_DEFINITIONS["MLA05-B"]
        if eval_result is None:
            # Evaluation was skipped (no Terraform)
            criteria.append(
                CriterionResult(
                    id="MLA05-B",
                    name=mla05_b["name"],
                    status=CriterionStatus.SKIP,
                    reason="Evaluation skipped - no Terraform configuration detected.",
                )
            )
        elif eval_result.success:
            criteria.append(
                CriterionResult(
                    id="MLA05-B",
                    name=mla05_b["name"],
                    status=CriterionStatus.PASS,
                    reason=mla05_b["pass_reason"],
                    details={"terraform_version": eval_result.terraform_version},
                )
            )
        elif eval_result.error_message and "not found" in eval_result.error_message.lower():
            # Tooling error - Terraform not installed
            criteria.append(
                CriterionResult(
                    id="MLA05-B",
                    name=mla05_b["name"],
                    status=CriterionStatus.ERROR,
                    reason=mla05_b["error_reason"],
                    details={"error": eval_result.error_message},
                )
            )
        else:
            # Validation failed
            criteria.append(
                CriterionResult(
                    id="MLA05-B",
                    name=mla05_b["name"],
                    status=CriterionStatus.ERROR,
                    reason=mla05_b["error_reason"],
                    details={"error": eval_result.error_message},
                )
            )

        # MLA05-C: Persistent Cycle Configured
        mla05_c = CRITERIA_DEFINITIONS["MLA05-C"]
        if trigger_event == "schedule":
            criteria.append(
                CriterionResult(
                    id="MLA05-C",
                    name=mla05_c["name"],
                    status=CriterionStatus.PASS,
                    reason=mla05_c["pass_reason"],
                    details={"trigger_event": trigger_event},
                )
            )
        else:
            criteria.append(
                CriterionResult(
                    id="MLA05-C",
                    name=mla05_c["name"],
                    status=CriterionStatus.FAIL,
                    reason=mla05_c["fail_reason"],
                    details={"trigger_event": trigger_event},
                )
            )

        # MLA05-D: Evidence Artifacts Generated
        mla05_d = CRITERIA_DEFINITIONS["MLA05-D"]
        if evidence_generated:
            criteria.append(
                CriterionResult(
                    id="MLA05-D",
                    name=mla05_d["name"],
                    status=CriterionStatus.PASS,
                    reason=mla05_d["pass_reason"],
                )
            )
        else:
            criteria.append(
                CriterionResult(
                    id="MLA05-D",
                    name=mla05_d["name"],
                    status=CriterionStatus.ERROR,
                    reason=mla05_d["error_reason"],
                )
            )

        return criteria

    def compute_overall_status(self, criteria: list[CriterionResult]) -> tuple[KSIStatus, list[str]]:
        """Compute overall KSI status from criteria.

        Rules:
        - ERROR if any criterion is ERROR
        - FAIL if any criterion is FAIL (and none ERROR)
        - PASS if all criteria are PASS or SKIP

        Args:
            criteria: List of criterion results

        Returns:
            Tuple of (overall status, list of reasons)
        """
        has_error = any(c.status == CriterionStatus.ERROR for c in criteria)
        has_fail = any(c.status == CriterionStatus.FAIL for c in criteria)

        reasons: list[str] = []
        for c in criteria:
            if c.status in (CriterionStatus.ERROR, CriterionStatus.FAIL):
                reasons.append(f"{c.id}: {c.reason}")

        if has_error:
            return KSIStatus.ERROR, reasons
        elif has_fail:
            return KSIStatus.FAIL, reasons
        else:
            return KSIStatus.PASS, ["All criteria passed."]

    def write_evaluation_manifest(
        self,
        detection: TerraformDetection,
        eval_result: TerraformEvalResult | None,
        process_info: ProcessInfo,
        scope_info: ScopeInfo,
    ) -> tuple[EvaluationManifest, KSIStatus]:
        """Write evaluation_manifest.json - the primary output file.

        Args:
            detection: Terraform detection results
            eval_result: Terraform evaluation results
            process_info: Workflow process information
            scope_info: Evaluation scope

        Returns:
            Tuple of (manifest, overall_status)
        """
        # Compute criteria
        criteria = self.compute_criteria(
            detection=detection,
            eval_result=eval_result,
            trigger_event=process_info.trigger_event,
            evidence_generated=True,  # We're generating it now
        )

        # Compute overall status
        status, reasons = self.compute_overall_status(criteria)

        manifest = EvaluationManifest(
            ksi_id=KSI_ID,
            requirement_text=KSI_REQUIREMENT_TEXT,
            status=status,
            reasons=reasons,
            evaluated_at=self.timestamp.isoformat(),
            scope=scope_info,
            process=process_info,
            criteria=criteria,
        )

        self.write_json_file(
            "evaluation_manifest.json",
            manifest.model_dump(),
            "Primary evaluation manifest with PASS/FAIL/ERROR status",
        )

        return manifest, status

    def write_manifest(self, repository: str, commit_sha: str) -> None:
        """Write manifest.json - index of all files."""
        files = [
            FileEntry(path=path, description=desc, schema_version="1.0")
            for path, desc in self.files_written
        ]

        manifest = EvidenceManifest(
            ksi_id=KSI_ID,
            generated_at=self.timestamp.isoformat(),
            commit_sha=commit_sha,
            repository=repository,
            files=files,
        )

        self.write_json_file(
            "manifest.json",
            manifest.model_dump(),
            "Index of all evidence files",
        )

    def write_hashes(self) -> None:
        """Write hashes.sha256 - SHA-256 hashes of all files."""
        hashes: list[str] = []

        for rel_path, _ in self.files_written:
            # Convert relative path to absolute
            abs_path = self.output_dir / rel_path
            if abs_path.exists():
                sha256 = hashlib.sha256()
                with open(abs_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                hashes.append(f"{sha256.hexdigest()}  {rel_path}")

        # Write hashes file
        hashes_path = self.evidence_dir / "hashes.sha256"
        with open(hashes_path, "w", encoding="utf-8") as f:
            f.write("\n".join(hashes) + "\n")

        self.files_written.append(
            ("evidence/ksi-mla-05/hashes.sha256", "SHA-256 hashes of all evidence files")
        )

    def create_zip(self, commit_sha: str) -> tuple[Path, str]:
        """Create the evidence pack zip file.

        Args:
            commit_sha: Commit SHA for artifact naming

        Returns:
            Tuple of (zip_path, artifact_name)
        """
        short_sha = commit_sha[:7]
        timestamp_str = self.timestamp.strftime("%Y%m%dT%H%M%SZ")
        artifact_name = f"{ARTIFACT_PREFIX}_{short_sha}_{timestamp_str}.zip"
        zip_path = self.output_dir / artifact_name

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel_path, _ in self.files_written:
                abs_path = self.output_dir / rel_path
                if abs_path.exists():
                    zf.write(abs_path, rel_path)

        return zip_path, artifact_name

    def write_results_summary(
        self,
        status: KSIStatus,
        artifact_name: str,
    ) -> None:
        """Write results.json - quick reference for the App.

        Args:
            status: Overall KSI status
            artifact_name: Name of the evidence artifact
        """
        summary_text = {
            KSIStatus.PASS: "All KSI-MLA-05 criteria passed. Terraform configuration evaluated successfully.",
            KSIStatus.FAIL: "KSI-MLA-05 evaluation failed. Review criteria results for details.",
            KSIStatus.ERROR: "KSI-MLA-05 evaluation encountered errors. Unable to determine compliance status.",
        }

        summary = ResultsSummary(
            ksi_id=KSI_ID,
            status=status,
            artifact_name=artifact_name,
            summary=summary_text[status],
        )

        # Write to output dir root (not in evidence subdir)
        results_path = self.output_dir / "results.json"
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(summary.model_dump(), f, indent=2)


def build_evidence_pack(
    output_dir: str | Path,
    detection: TerraformDetection,
    inventory: TerraformInventory | None,
    eval_result: TerraformEvalResult | None,
    repository: str,
    commit_sha: str,
    workflow_name: str,
    workflow_run_id: str,
    workflow_run_url: str,
    trigger_event: str,
    actor: str,
    terraform_version: str | None = None,
) -> tuple[Path, str, KSIStatus]:
    """Build complete evidence pack.

    Args:
        output_dir: Directory to write evidence
        detection: Terraform detection results
        inventory: Terraform inventory (None if no TF detected)
        eval_result: Terraform evaluation results (None if not run)
        repository: Repository name (owner/repo)
        commit_sha: Full commit SHA
        workflow_name: Name of the workflow
        workflow_run_id: Workflow run ID
        workflow_run_url: URL to workflow run
        trigger_event: Event that triggered workflow
        actor: User/bot that triggered workflow
        terraform_version: Terraform version if available

    Returns:
        Tuple of (zip_path, artifact_name, overall_status)
    """
    builder = EvidencePackBuilder(output_dir)
    builder.setup_directories()

    # Write supporting files
    builder.write_collected_at()
    builder.write_scope(repository, commit_sha, detection.tf_paths)
    builder.write_tools(terraform_version)

    # Write declared files
    builder.write_terraform_detection(detection)
    if inventory:
        builder.write_terraform_inventory(inventory)

    # Build process and scope info
    process_info = ProcessInfo(
        workflow_name=workflow_name,
        workflow_run_id=workflow_run_id,
        workflow_run_url=workflow_run_url,
        trigger_event=trigger_event,
        commit_sha=commit_sha,
        repository=repository,
        actor=actor,
    )

    scope_info = ScopeInfo(
        repository=repository,
        commit_sha=commit_sha,
        configuration_surfaces=["TERRAFORM"],
        terraform_paths=detection.tf_paths,
    )

    # Write evaluation manifest
    manifest, status = builder.write_evaluation_manifest(
        detection=detection,
        eval_result=eval_result,
        process_info=process_info,
        scope_info=scope_info,
    )

    # Write manifest index
    builder.write_manifest(repository, commit_sha)

    # Write hashes (must be after all other files)
    builder.write_hashes()

    # Create zip
    zip_path, artifact_name = builder.create_zip(commit_sha)

    # Write results summary (outside zip, for easy access)
    builder.write_results_summary(status, artifact_name)

    return zip_path, artifact_name, status
