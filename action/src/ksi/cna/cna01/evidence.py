"""Evidence pack generation for KSI-CNA-01.

Generates the evidence pack artifact for CNA-01: Restrict Network Traffic.
"""

import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.constants_cna import (
    CNA01_APPLIES_TO,
    CNA01_ARTIFACT_PREFIX,
    CNA01_KSI_ID,
    CNA01_KSI_NAME,
    CNA01_RELATED_CONTROLS,
    CNA01_REQUIREMENT_TEXT,
)
from shared.schemas_network import (
    CNA01CriterionResult,
    CNA01EvaluationManifest,
    CNA01Summary,
    NetworkInventory,
)


class CNA01EvidencePackBuilder:
    """Builder for FedRAMP KSI-CNA-01 evidence pack."""

    def __init__(self, output_dir: str | Path = "."):
        """Initialize the evidence pack builder.

        Args:
            output_dir: Directory to write evidence files
        """
        self.output_dir = Path(output_dir).resolve()
        self.evidence_dir = self.output_dir / "evidence" / "ksi-cna-01"
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
            rel_path = f"evidence/ksi-cna-01/{subdir}/{filename}"
        else:
            target_dir = self.evidence_dir
            rel_path = f"evidence/ksi-cna-01/{filename}"

        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / filename

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        self.files_written.append((rel_path, description))
        return file_path

    def write_collected_at(self) -> None:
        """Write collected_at.json."""
        data = {
            "schema_version": "1.0",
            "timestamp": self.timestamp.isoformat(),
            "timezone": "UTC",
        }
        self.write_json_file(
            "collected_at.json",
            data,
            "Timestamp of evidence collection",
        )

    def write_scope(
        self,
        repository: str,
        commit_sha: str,
        tf_paths: list[str],
    ) -> None:
        """Write scope.json."""
        data = {
            "schema_version": "1.0",
            "repository": repository,
            "commit_sha": commit_sha,
            "configuration_surfaces": ["TERRAFORM"],
            "terraform_paths": tf_paths,
            "ksi_id": CNA01_KSI_ID,
            "ksi_name": CNA01_KSI_NAME,
        }
        self.write_json_file(
            "scope.json",
            data,
            "Scope of the evaluation",
        )

    def write_tools(
        self,
        terraform_version: str | None,
        action_version: str = "1.0.0",
    ) -> None:
        """Write tools.json."""
        data = {
            "schema_version": "1.0",
            "terraform_version": terraform_version,
            "action_version": action_version,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
        self.write_json_file(
            "tools.json",
            data,
            "Tools and versions used for evaluation",
        )

    def write_network_inventory(self, inventory: NetworkInventory) -> None:
        """Write network_inventory.json."""
        self.write_json_file(
            "network_inventory.json",
            inventory.model_dump(),
            "Network inventory extracted from Terraform configuration",
            subdir="declared",
        )

    def write_evaluation_manifest(
        self,
        criteria: dict[str, CNA01CriterionResult],
        summary: CNA01Summary,
        repository: str,
        commit_sha: str,
        trigger_event: str,
    ) -> CNA01EvaluationManifest:
        """Write evaluation_manifest.json - the primary output file.

        Args:
            criteria: Evaluated criteria results
            summary: Evaluation summary
            repository: Repository name
            commit_sha: Commit SHA
            trigger_event: GitHub event that triggered workflow

        Returns:
            The evaluation manifest
        """
        manifest = CNA01EvaluationManifest(
            evaluated_at=self.timestamp.isoformat(),
            trigger_event=trigger_event,
            repository=repository,
            commit_sha=commit_sha,
            criteria=criteria,
            summary=summary,
        )

        self.write_json_file(
            "evaluation_manifest.json",
            manifest.model_dump(),
            "Primary evaluation manifest with PASS/FAIL/ERROR status",
        )

        return manifest

    def write_manifest(self, repository: str, commit_sha: str) -> None:
        """Write manifest.json - index of all files."""
        files = [
            {
                "path": path,
                "description": desc,
                "schema_version": "1.0",
            }
            for path, desc in self.files_written
        ]

        manifest = {
            "schema_version": "1.0",
            "ksi_id": CNA01_KSI_ID,
            "generated_at": self.timestamp.isoformat(),
            "commit_sha": commit_sha,
            "repository": repository,
            "files": files,
        }

        self.write_json_file(
            "manifest.json",
            manifest,
            "Index of all evidence files",
        )

    def write_hashes(self) -> None:
        """Write hashes.sha256 - SHA-256 hashes of all files."""
        hashes: list[str] = []

        for rel_path, _ in self.files_written:
            abs_path = self.output_dir / rel_path
            if abs_path.exists():
                sha256 = hashlib.sha256()
                with open(abs_path, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                hashes.append(f"{sha256.hexdigest()}  {rel_path}")

        hashes_path = self.evidence_dir / "hashes.sha256"
        with open(hashes_path, "w", encoding="utf-8") as f:
            f.write("\n".join(hashes) + "\n")

        self.files_written.append(
            ("evidence/ksi-cna-01/hashes.sha256", "SHA-256 hashes of all evidence files")
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
        artifact_name = f"{CNA01_ARTIFACT_PREFIX}_{short_sha}_{timestamp_str}.zip"
        zip_path = self.output_dir / artifact_name

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel_path, _ in self.files_written:
                abs_path = self.output_dir / rel_path
                if abs_path.exists():
                    zf.write(abs_path, rel_path)

        return zip_path, artifact_name


def build_cna01_evidence_pack(
    output_dir: str | Path,
    inventory: NetworkInventory,
    criteria: dict[str, CNA01CriterionResult],
    summary: CNA01Summary,
    repository: str,
    commit_sha: str,
    trigger_event: str,
    tf_paths: list[str],
    terraform_version: str | None = None,
) -> tuple[Path, str, str]:
    """Build complete CNA-01 evidence pack.

    Args:
        output_dir: Directory to write evidence
        inventory: Network inventory from Terraform
        criteria: Evaluated criteria results
        summary: Evaluation summary
        repository: Repository name (owner/repo)
        commit_sha: Full commit SHA
        trigger_event: Event that triggered workflow
        tf_paths: Paths containing Terraform configuration
        terraform_version: Terraform version if available

    Returns:
        Tuple of (zip_path, artifact_name, overall_status)
    """
    builder = CNA01EvidencePackBuilder(output_dir)
    builder.setup_directories()

    # Write supporting files
    builder.write_collected_at()
    builder.write_scope(repository, commit_sha, tf_paths)
    builder.write_tools(terraform_version)

    # Write network inventory
    builder.write_network_inventory(inventory)

    # Write evaluation manifest
    builder.write_evaluation_manifest(
        criteria=criteria,
        summary=summary,
        repository=repository,
        commit_sha=commit_sha,
        trigger_event=trigger_event,
    )

    # Write manifest index
    builder.write_manifest(repository, commit_sha)

    # Write hashes (must be after all other files)
    builder.write_hashes()

    # Create zip
    zip_path, artifact_name = builder.create_zip(commit_sha)

    return zip_path, artifact_name, summary.status
