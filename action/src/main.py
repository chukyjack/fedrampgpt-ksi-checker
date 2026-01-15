#!/usr/bin/env python3
"""Main orchestrator for FedRAMP KSI-MLA-05 GitHub Action.

This is the entry point that coordinates detection, evaluation,
inventory generation, and evidence pack creation.
"""

import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.schemas import KSIStatus

from action.src.detect import get_tf_root_paths, scan_for_terraform
from action.src.evaluate import evaluate_terraform
from action.src.evidence import build_evidence_pack
from action.src.inventory import generate_inventory


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

    print(f"FedRAMP KSI-MLA-05 Evaluation")
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

    # Variables for evidence pack
    eval_result = None
    inventory = None
    terraform_version = None

    if not detection.detected:
        log_warning("No Terraform configuration detected in repository")
    else:
        # Step 2: Terraform Evaluation
        log_group("Step 2: Terraform Evaluation")
        tf_roots = get_tf_root_paths(detection)
        print(f"Evaluating Terraform in: {tf_roots}")

        for tf_root in tf_roots:
            eval_path = workspace / tf_root if tf_root != "." else workspace
            print(f"\nEvaluating: {eval_path}")
            eval_result = evaluate_terraform(eval_path)
            terraform_version = eval_result.terraform_version

            print(f"  Terraform version: {eval_result.terraform_version or 'N/A'}")
            print(f"  Init success: {eval_result.init_success}")
            print(f"  Validate success: {eval_result.validate_success}")

            if eval_result.error_message:
                log_error(eval_result.error_message)

        log_group_end()

        # Step 3: Generate Inventory
        log_group("Step 3: Generate Terraform Inventory")
        inventory = generate_inventory(workspace, detection.tf_paths)
        print(f"Resources: {inventory.resources.total_count} total")
        print(f"  By type: {list(inventory.resources.by_type.keys())}")
        print(f"Providers: {[p.name for p in inventory.providers]}")
        print(f"Modules: {[m.name for m in inventory.modules]}")
        print(f"Files analyzed: {len(inventory.files_analyzed)}")
        log_group_end()

    # Step 4: Build Evidence Pack
    log_group("Step 4: Generate Evidence Pack")
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
    print(f"Location: {zip_path}")
    print(f"Status: {status.value}")
    log_group_end()

    # Set outputs
    set_output("status", status.value)
    set_output("artifact_name", artifact_name)
    set_output("artifact_path", str(zip_path))
    set_output("evidence_dir", str(output_dir / "evidence"))

    # Generate summary
    summary_lines = [
        f"## FedRAMP KSI-MLA-05 Evaluation Results",
        "",
        f"**Status:** {status.value}",
        f"**Repository:** {ctx['repository']}",
        f"**Commit:** `{ctx['commit_sha'][:7]}`",
        f"**Trigger:** `{ctx['trigger_event']}`",
        "",
        "### Criteria Results",
        "",
    ]

    # Read evaluation manifest for criteria details
    manifest_path = output_dir / "evidence" / "ksi-mla-05" / "evaluation_manifest.json"
    if manifest_path.exists():
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
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

    summary_lines.extend([
        "",
        "### Evidence Artifact",
        f"- **Name:** `{artifact_name}`",
        "",
    ])

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
    print(f"KSI-MLA-05 Status: {status.value}")
    print("=" * 60)

    # Return appropriate exit code
    # Note: We always return 0 so the workflow continues and artifacts are uploaded
    # The status is communicated via outputs
    return 0


if __name__ == "__main__":
    sys.exit(main())
