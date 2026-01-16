#!/usr/bin/env python3
"""Main orchestrator for FedRAMP KSI GitHub Action.

This is the entry point that coordinates detection, evaluation,
inventory generation, and evidence pack creation for all KSIs.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.schemas import KSIStatus

from action.src.detect import get_tf_root_paths, scan_for_terraform
from action.src.evaluate import evaluate_terraform
from action.src.evidence import build_evidence_pack
from action.src.inventory import generate_inventory

# CNA-01 imports
from action.src.ksi.cna.cna01.evaluator import evaluate_cna01
from action.src.ksi.cna.cna01.evidence import build_cna01_evidence_pack
from action.src.ksi.cna.shared.network_inventory import extract_network_inventory


def get_github_context() -> dict[str, str]:
    """Get GitHub Actions context from environment variables.

    Returns:
        Dict with GitHub context values
    """
    # Build workflow run URL
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")
    run_id = os.environ.get("GITHUB_RUN_ID", "0")
    workflow_run_url = f"{server_url}/{repository}/actions/runs/{run_id}"

    return {
        "repository": repository,
        "commit_sha": os.environ.get("GITHUB_SHA", "0" * 40),
        "workflow_name": os.environ.get("GITHUB_WORKFLOW", "FedRAMP KSI Evidence"),
        "workflow_run_id": run_id,
        "workflow_run_url": workflow_run_url,
        "trigger_event": os.environ.get("GITHUB_EVENT_NAME", "unknown"),
        "actor": os.environ.get("GITHUB_ACTOR", "unknown"),
        "workspace": os.environ.get("GITHUB_WORKSPACE", os.getcwd()),
    }


def set_output(name: str, value: str) -> None:
    """Set a GitHub Actions output.

    Args:
        name: Output name
        value: Output value
    """
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as f:
            # Handle multiline values
            if "\n" in value:
                import uuid
                delimiter = uuid.uuid4().hex
                f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
            else:
                f.write(f"{name}={value}\n")
    else:
        # Fallback for local testing
        print(f"::set-output name={name}::{value}")


def log_group(title: str) -> None:
    """Start a GitHub Actions log group."""
    print(f"::group::{title}")


def log_group_end() -> None:
    """End a GitHub Actions log group."""
    print("::endgroup::")


def log_error(message: str) -> None:
    """Log an error message."""
    print(f"::error::{message}")


def log_warning(message: str) -> None:
    """Log a warning message."""
    print(f"::warning::{message}")


def run_mla05(
    workspace: Path,
    output_dir: Path,
    ctx: dict[str, str],
    detection,
    terraform_version: str | None,
) -> dict:
    """Run KSI-MLA-05 evaluation.

    Args:
        workspace: Repository workspace path
        output_dir: Output directory for evidence
        ctx: GitHub context
        detection: Terraform detection result
        terraform_version: Terraform version

    Returns:
        Dict with KSI result info
    """
    eval_result = None
    inventory = None

    if detection.detected:
        # Step 2: Terraform Evaluation
        log_group("MLA-05: Terraform Evaluation")
        tf_roots = get_tf_root_paths(detection)
        print(f"Evaluating Terraform in: {tf_roots}")

        for tf_root in tf_roots:
            eval_path = workspace / tf_root if tf_root != "." else workspace
            print(f"\nEvaluating: {eval_path}")
            eval_result = evaluate_terraform(eval_path)

            print(f"  Terraform version: {eval_result.terraform_version or 'N/A'}")
            print(f"  Init success: {eval_result.init_success}")
            print(f"  Validate success: {eval_result.validate_success}")

            if eval_result.error_message:
                log_error(eval_result.error_message)

        log_group_end()

        # Step 3: Generate Inventory
        log_group("MLA-05: Generate Terraform Inventory")
        inventory = generate_inventory(workspace, detection.tf_paths)
        print(f"Resources: {inventory.resources.total_count} total")
        print(f"  By type: {list(inventory.resources.by_type.keys())}")
        print(f"Providers: {[p.name for p in inventory.providers]}")
        print(f"Modules: {[m.name for m in inventory.modules]}")
        print(f"Files analyzed: {len(inventory.files_analyzed)}")
        log_group_end()

    # Build Evidence Pack
    log_group("MLA-05: Generate Evidence Pack")
    zip_path, artifact_name, status = build_evidence_pack(
        output_dir=output_dir,
        detection=detection,
        inventory=inventory,
        eval_result=eval_result,
        repository=ctx["repository"],
        commit_sha=ctx["commit_sha"],
        workflow_name=ctx["workflow_name"],
        workflow_run_id=ctx["workflow_run_id"],
        workflow_run_url=ctx["workflow_run_url"],
        trigger_event=ctx["trigger_event"],
        actor=ctx["actor"],
        terraform_version=terraform_version,
    )
    print(f"Evidence pack created: {artifact_name}")
    print(f"Status: {status.value}")
    log_group_end()

    return {
        "ksi_id": "KSI-MLA-05",
        "ksi_name": "Evaluate Configuration",
        "status": status.value,
        "evidence_path": "evidence/ksi-mla-05/evaluation_manifest.json",
        "artifact_name": artifact_name,
        "zip_path": str(zip_path),
    }


def run_cna01(
    workspace: Path,
    output_dir: Path,
    ctx: dict[str, str],
    detection,
    terraform_version: str | None,
) -> dict:
    """Run KSI-CNA-01 evaluation.

    Args:
        workspace: Repository workspace path
        output_dir: Output directory for evidence
        ctx: GitHub context
        detection: Terraform detection result
        terraform_version: Terraform version

    Returns:
        Dict with KSI result info
    """
    # Extract network inventory
    log_group("CNA-01: Extract Network Inventory")
    network_inventory = extract_network_inventory(workspace, detection.tf_paths)
    print(f"Security groups found: {len(network_inventory.security_groups)}")
    print(f"VPCs found: {len(network_inventory.vpcs)}")
    print(f"Subnets found: {len(network_inventory.subnets)}")
    print(f"Load balancers found: {len(network_inventory.load_balancers)}")
    print(f"Files analyzed: {len(network_inventory.source_files)}")
    log_group_end()

    # Evaluate CNA-01 criteria
    log_group("CNA-01: Evaluate Criteria")
    criteria, summary = evaluate_cna01(network_inventory, ctx["trigger_event"])

    for criterion_id, result in criteria.items():
        status_emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(
            result.status, "❓"
        )
        print(f"  {status_emoji} {criterion_id}: {result.status}")
        if result.findings:
            for finding in result.findings[:3]:  # Show first 3 findings
                print(f"      - {finding.issue}")
            if len(result.findings) > 3:
                print(f"      ... and {len(result.findings) - 3} more findings")

    print(f"\nOverall: {summary.status}")
    print(f"  Security groups evaluated: {summary.security_groups_evaluated}")
    print(f"  Compliant: {summary.security_groups_compliant}")
    print(f"  Non-compliant: {summary.security_groups_non_compliant}")
    log_group_end()

    # Build Evidence Pack
    log_group("CNA-01: Generate Evidence Pack")
    zip_path, artifact_name, status = build_cna01_evidence_pack(
        output_dir=output_dir,
        inventory=network_inventory,
        criteria=criteria,
        summary=summary,
        repository=ctx["repository"],
        commit_sha=ctx["commit_sha"],
        trigger_event=ctx["trigger_event"],
        tf_paths=detection.tf_paths,
        terraform_version=terraform_version,
    )
    print(f"Evidence pack created: {artifact_name}")
    print(f"Status: {status}")
    log_group_end()

    return {
        "ksi_id": "KSI-CNA-01",
        "ksi_name": "Restrict Network Traffic",
        "status": status,
        "evidence_path": "evidence/ksi-cna-01/evaluation_manifest.json",
        "artifact_name": artifact_name,
        "zip_path": str(zip_path),
    }


def write_multi_ksi_results(
    output_dir: Path,
    ksi_results: list[dict],
    ctx: dict[str, str],
) -> None:
    """Write the multi-KSI results.json file.

    Args:
        output_dir: Output directory
        ksi_results: List of KSI result dicts
        ctx: GitHub context
    """
    results = {
        "schema_version": "1.0",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "trigger_event": ctx["trigger_event"],
        "repository": ctx["repository"],
        "commit_sha": ctx["commit_sha"],
        "ksi_results": [
            {
                "ksi_id": r["ksi_id"],
                "ksi_name": r["ksi_name"],
                "status": r["status"],
                "evidence_path": r["evidence_path"],
            }
            for r in ksi_results
        ],
    }

    results_path = output_dir / "results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def main() -> int:
    """Main entry point for the action.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Get configuration
    root_paths = os.environ.get("INPUT_ROOT_PATHS", ".").split(",")
    root_paths = [p.strip() for p in root_paths if p.strip()]

    # Get GitHub context
    ctx = get_github_context()
    workspace = Path(ctx["workspace"])
    output_dir = workspace / ".fedramp-evidence"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("FedRAMP 20x KSI Evidence Evaluation")
    print("=" * 60)
    print(f"Repository: {ctx['repository']}")
    print(f"Commit: {ctx['commit_sha'][:7]}")
    print(f"Trigger: {ctx['trigger_event']}")
    print()

    # Step 1: Detect Terraform
    log_group("Step 1: Terraform Detection")
    detection = scan_for_terraform(workspace)
    print(f"Terraform detected: {detection.detected}")
    print(f"Files found: {detection.tf_file_count}")
    print(f"Paths: {detection.tf_paths}")
    print(f"Lockfile present: {detection.lockfile_present}")
    log_group_end()

    # Track terraform version
    terraform_version = None

    if not detection.detected:
        log_warning("No Terraform configuration detected in repository")
    else:
        # Quick terraform version check
        from action.src.evaluate import get_terraform_version
        terraform_version = get_terraform_version()

    # Collect results from all KSIs
    ksi_results: list[dict] = []

    # Run MLA-05
    print()
    print("-" * 60)
    print("KSI-MLA-05: Evaluate Configuration")
    print("-" * 60)
    mla05_result = run_mla05(workspace, output_dir, ctx, detection, terraform_version)
    ksi_results.append(mla05_result)

    # Run CNA-01
    print()
    print("-" * 60)
    print("KSI-CNA-01: Restrict Network Traffic")
    print("-" * 60)
    cna01_result = run_cna01(workspace, output_dir, ctx, detection, terraform_version)
    ksi_results.append(cna01_result)

    # Write combined results.json
    write_multi_ksi_results(output_dir, ksi_results, ctx)

    # Set outputs (use MLA-05 artifact for backward compatibility)
    set_output("status", mla05_result["status"])
    set_output("artifact_name", mla05_result["artifact_name"])
    set_output("artifact_path", mla05_result["zip_path"])
    set_output("evidence_dir", str(output_dir / "evidence"))

    # Also set CNA-01 specific outputs
    set_output("cna01_status", cna01_result["status"])
    set_output("cna01_artifact_name", cna01_result["artifact_name"])

    # Generate summary
    summary_lines = [
        "## FedRAMP 20x KSI Evidence Evaluation Results",
        "",
        f"**Repository:** {ctx['repository']}",
        f"**Commit:** `{ctx['commit_sha'][:7]}`",
        f"**Trigger:** `{ctx['trigger_event']}`",
        "",
        "### KSI Results",
        "",
        "| KSI | Name | Status |",
        "|-----|------|--------|",
    ]

    for result in ksi_results:
        status_emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(
            result["status"], "❓"
        )
        summary_lines.append(
            f"| {result['ksi_id']} | {result['ksi_name']} | {status_emoji} {result['status']} |"
        )

    summary_lines.extend([
        "",
        "### Evidence Artifacts",
        "",
    ])

    for result in ksi_results:
        summary_lines.append(f"- **{result['ksi_id']}:** `{result['artifact_name']}`")

    # Add criteria details for each KSI
    summary_lines.extend([
        "",
        "---",
        "",
    ])

    # MLA-05 criteria details
    mla05_manifest_path = output_dir / "evidence" / "ksi-mla-05" / "evaluation_manifest.json"
    if mla05_manifest_path.exists():
        with open(mla05_manifest_path, "r") as f:
            manifest = json.load(f)
        summary_lines.append("### KSI-MLA-05 Criteria Details")
        summary_lines.append("")
        for criterion in manifest.get("criteria", []):
            status_emoji = {
                "PASS": "✅",
                "FAIL": "❌",
                "ERROR": "⚠️",
                "SKIP": "⏭️",
            }.get(criterion["status"], "❓")
            summary_lines.append(
                f"- {status_emoji} **{criterion['id']}** ({criterion['name']}): {criterion['status']}"
            )
            summary_lines.append(f"  - {criterion['reason']}")
        summary_lines.append("")

    # CNA-01 criteria details
    cna01_manifest_path = output_dir / "evidence" / "ksi-cna-01" / "evaluation_manifest.json"
    if cna01_manifest_path.exists():
        with open(cna01_manifest_path, "r") as f:
            manifest = json.load(f)
        summary_lines.append("### KSI-CNA-01 Criteria Details")
        summary_lines.append("")
        for criterion_id, criterion in manifest.get("criteria", {}).items():
            status_emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(
                criterion["status"], "❓"
            )
            summary_lines.append(
                f"- {status_emoji} **{criterion['id']}** ({criterion['name']}): {criterion['status']}"
            )
            if criterion.get("findings"):
                finding_count = len(criterion["findings"])
                summary_lines.append(f"  - {finding_count} finding(s)")
        summary_lines.append("")

    summary = "\n".join(summary_lines)
    set_output("summary", summary)

    # Write to GitHub Step Summary
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write(summary)

    # Print final status
    print()
    print("=" * 60)
    print("Final Results")
    print("=" * 60)
    for result in ksi_results:
        print(f"  {result['ksi_id']}: {result['status']}")
    print("=" * 60)

    # Return appropriate exit code
    # Note: We always return 0 so the workflow continues and artifacts are uploaded
    # The status is communicated via outputs
    return 0


if __name__ == "__main__":
    sys.exit(main())
