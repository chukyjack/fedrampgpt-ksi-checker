"""GitHub Check Run management."""

from typing import Any

import httpx

from app.config import get_settings
from app.github_auth import github_auth
from shared.constants import CHECK_RUN_NAME, CHECK_RUN_TITLE, KSI_REQUIREMENT_TEXT
from shared.constants_cna import (
    CNA01_KSI_ID,
    CNA01_KSI_NAME,
    CNA01_REQUIREMENT_TEXT,
)


# KSI metadata registry for building check run summaries
KSI_METADATA = {
    "KSI-MLA-05": {
        "check_run_name": CHECK_RUN_NAME,
        "check_run_title": CHECK_RUN_TITLE,
        "requirement_text": KSI_REQUIREMENT_TEXT,
        "ksi_name": "Evaluate Configuration",
    },
    "KSI-CNA-01": {
        "check_run_name": f"{CNA01_KSI_ID} — {CNA01_KSI_NAME}",
        "check_run_title": f"FedRAMP 20x KSI Evidence: {CNA01_KSI_ID} {CNA01_KSI_NAME}",
        "requirement_text": CNA01_REQUIREMENT_TEXT,
        "ksi_name": CNA01_KSI_NAME,
    },
}


def get_ksi_metadata(ksi_id: str) -> dict[str, str]:
    """Get metadata for a KSI.

    Args:
        ksi_id: KSI identifier like 'KSI-MLA-05'

    Returns:
        Dict with check_run_name, check_run_title, requirement_text, ksi_name
    """
    if ksi_id in KSI_METADATA:
        return KSI_METADATA[ksi_id]

    # Fallback for unknown KSIs
    return {
        "check_run_name": f"{ksi_id} — Evaluation",
        "check_run_title": f"FedRAMP 20x KSI Evidence: {ksi_id}",
        "requirement_text": f"FedRAMP 20x Key Security Indicator: {ksi_id}",
        "ksi_name": "Evaluation",
    }


def status_to_conclusion(status: str) -> str:
    """Map KSI status to GitHub Check Run conclusion.

    Args:
        status: KSI status (PASS, FAIL, ERROR)

    Returns:
        GitHub conclusion string
    """
    mapping = {
        "PASS": "success",
        "FAIL": "failure",
        "ERROR": "neutral",  # As per spec, use neutral for errors
    }
    return mapping.get(status, "neutral")


def build_check_run_summary(
    manifest: dict[str, Any],
    artifact_name: str | None = None,
    run_url: str | None = None,
    ksi_id: str = "KSI-MLA-05",
) -> str:
    """Build the Check Run summary markdown.

    Uses locked FedRAMP wording as specified.

    Args:
        manifest: Evaluation manifest dict
        artifact_name: Name of the evidence artifact
        run_url: URL to the workflow run
        ksi_id: KSI identifier (e.g., 'KSI-MLA-05', 'KSI-CNA-01')

    Returns:
        Markdown summary string
    """
    ksi_meta = get_ksi_metadata(ksi_id)

    # Handle different manifest structures
    # MLA-05 has 'status' at top level, CNA-01 has 'summary.status'
    summary_data = manifest.get("summary", {})
    status = summary_data.get("status") if summary_data else manifest.get("status", "UNKNOWN")

    # Get scope - MLA-05 has 'scope', CNA-01 uses top-level fields
    scope = manifest.get("scope", {})
    if not scope:
        # CNA-01 style: fields are at top level
        scope = {
            "repository": manifest.get("repository", "N/A"),
            "commit_sha": manifest.get("commit_sha", "N/A"),
            "configuration_surfaces": ["TERRAFORM"],
        }

    # Get process info - MLA-05 has 'process', CNA-01 has trigger_event at top level
    process = manifest.get("process", {})
    if not process:
        # CNA-01 style
        process = {
            "trigger_event": manifest.get("trigger_event", "N/A"),
        }

    # Get criteria - MLA-05 has list, CNA-01 has dict
    criteria = manifest.get("criteria", [])
    is_criteria_dict = isinstance(criteria, dict)

    # Status emoji
    status_emoji = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(status, "❓")

    lines = [
        f"## {status_emoji} {ksi_id}: {ksi_meta['ksi_name']}",
        "",
        "### Requirement",
        f"> {ksi_meta['requirement_text']}",
        "",
        f"### Status: **{status}**",
        "",
    ]

    # CNA-01 summary stats
    if summary_data and "security_groups_evaluated" in summary_data:
        lines.append("### Summary")
        lines.append(f"- **Security Groups Evaluated:** {summary_data.get('security_groups_evaluated', 0)}")
        lines.append(f"- **Compliant:** {summary_data.get('security_groups_compliant', 0)}")
        lines.append(f"- **Non-Compliant:** {summary_data.get('security_groups_non_compliant', 0)}")
        lines.append("")

    # MLA-05 reasons
    reasons = manifest.get("reasons", [])
    if reasons:
        lines.append("### Summary")
        for reason in reasons:
            lines.append(f"- {reason}")
        lines.append("")

    # Criteria results
    lines.append("### Criteria Evaluation")
    lines.append("")
    lines.append("| Criterion | Name | Status | Details |")
    lines.append("|-----------|------|--------|---------|")

    if is_criteria_dict:
        # CNA-01 style: dict with criterion IDs as keys
        for crit_id, criterion in criteria.items():
            crit_status = criterion.get("status", "UNKNOWN")
            crit_emoji = {
                "PASS": "✅",
                "FAIL": "❌",
                "ERROR": "⚠️",
                "SKIP": "⏭️",
            }.get(crit_status, "❓")
            # Show finding count for CNA-01
            findings = criterion.get("findings", [])
            details = f"{len(findings)} finding(s)" if findings else criterion.get("reason", "N/A")
            lines.append(
                f"| {criterion.get('id', crit_id)} | {criterion.get('name', 'N/A')} | {crit_emoji} {crit_status} | {details} |"
            )
    else:
        # MLA-05 style: list of criterion dicts
        for criterion in criteria:
            crit_status = criterion.get("status", "UNKNOWN")
            crit_emoji = {
                "PASS": "✅",
                "FAIL": "❌",
                "ERROR": "⚠️",
                "SKIP": "⏭️",
            }.get(crit_status, "❓")
            lines.append(
                f"| {criterion.get('id', 'N/A')} | {criterion.get('name', 'N/A')} | {crit_emoji} {crit_status} | {criterion.get('reason', 'N/A')} |"
            )

    lines.append("")

    # Scope
    lines.append("### Scope")
    repo = scope.get("repository", "N/A")
    commit = scope.get("commit_sha", "N/A")
    lines.append(f"- **Repository:** {repo}")
    lines.append(f"- **Commit:** `{commit[:7] if len(commit) > 7 else commit}`")
    config_surfaces = scope.get("configuration_surfaces", [])
    if config_surfaces:
        lines.append(f"- **Configuration Surfaces:** {', '.join(config_surfaces)}")
    tf_paths = scope.get("terraform_paths", [])
    if tf_paths:
        lines.append(f"- **Terraform Paths:** {', '.join(tf_paths)}")
    lines.append("")

    # Process
    lines.append("### Process")
    if process.get("workflow_name"):
        lines.append(f"- **Workflow:** {process.get('workflow_name', 'N/A')}")
    lines.append(f"- **Trigger:** `{process.get('trigger_event', manifest.get('trigger_event', 'N/A'))}`")
    if run_url and process.get("workflow_run_id"):
        lines.append(f"- **Run:** [{process.get('workflow_run_id', 'N/A')}]({run_url})")
    elif process.get("workflow_run_id"):
        lines.append(f"- **Run ID:** {process.get('workflow_run_id', 'N/A')}")
    if process.get("actor"):
        lines.append(f"- **Actor:** {process.get('actor', 'N/A')}")
    lines.append("")

    # Evidence artifact
    if artifact_name:
        lines.append("### Evidence Artifact")
        lines.append(f"- **Name:** `{artifact_name}`")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Generated by FedRAMP 20x KSI Evidence Action*")

    return "\n".join(lines)


async def create_check_run(
    installation_id: int,
    owner: str,
    repo: str,
    head_sha: str,
    manifest: dict[str, Any],
    artifact_name: str | None = None,
    run_url: str | None = None,
    ksi_id: str = "KSI-MLA-05",
) -> dict[str, Any]:
    """Create a Check Run for KSI evaluation results.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        head_sha: Commit SHA to attach check to
        manifest: Evaluation manifest
        artifact_name: Name of the evidence artifact
        run_url: URL to the workflow run
        ksi_id: KSI identifier (e.g., 'KSI-MLA-05', 'KSI-CNA-01')

    Returns:
        Created check run data
    """
    token = await github_auth.get_installation_token(installation_id)
    settings = get_settings()
    ksi_meta = get_ksi_metadata(ksi_id)

    # Handle different manifest structures for status
    summary_data = manifest.get("summary", {})
    status = summary_data.get("status") if summary_data else manifest.get("status", "ERROR")
    conclusion = status_to_conclusion(status)
    summary = build_check_run_summary(manifest, artifact_name, run_url, ksi_id)

    payload = {
        "name": ksi_meta["check_run_name"],
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": ksi_meta["check_run_title"],
            "summary": summary,
        },
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.github_api_url}/repos/{owner}/{repo}/check-runs",
            headers=github_auth.get_headers(token),
            json=payload,
        )
        response.raise_for_status()

    return response.json()


async def update_check_run(
    installation_id: int,
    owner: str,
    repo: str,
    check_run_id: int,
    manifest: dict[str, Any],
    artifact_name: str | None = None,
    run_url: str | None = None,
    ksi_id: str = "KSI-MLA-05",
) -> dict[str, Any]:
    """Update an existing Check Run.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        check_run_id: ID of the check run to update
        manifest: Evaluation manifest
        artifact_name: Name of the evidence artifact
        run_url: URL to the workflow run
        ksi_id: KSI identifier (e.g., 'KSI-MLA-05', 'KSI-CNA-01')

    Returns:
        Updated check run data
    """
    token = await github_auth.get_installation_token(installation_id)
    settings = get_settings()
    ksi_meta = get_ksi_metadata(ksi_id)

    # Handle different manifest structures for status
    summary_data = manifest.get("summary", {})
    status = summary_data.get("status") if summary_data else manifest.get("status", "ERROR")
    conclusion = status_to_conclusion(status)
    summary = build_check_run_summary(manifest, artifact_name, run_url, ksi_id)

    payload = {
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": ksi_meta["check_run_title"],
            "summary": summary,
        },
    }

    async with httpx.AsyncClient() as client:
        response = await client.patch(
            f"{settings.github_api_url}/repos/{owner}/{repo}/check-runs/{check_run_id}",
            headers=github_auth.get_headers(token),
            json=payload,
        )
        response.raise_for_status()

    return response.json()


async def find_existing_check_run(
    installation_id: int,
    owner: str,
    repo: str,
    head_sha: str,
    ksi_id: str = "KSI-MLA-05",
) -> dict[str, Any] | None:
    """Find an existing check run for a commit.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        head_sha: Commit SHA
        ksi_id: KSI identifier (e.g., 'KSI-MLA-05', 'KSI-CNA-01')

    Returns:
        Check run data or None if not found
    """
    token = await github_auth.get_installation_token(installation_id)
    settings = get_settings()
    ksi_meta = get_ksi_metadata(ksi_id)

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.github_api_url}/repos/{owner}/{repo}/commits/{head_sha}/check-runs",
            headers=github_auth.get_headers(token),
            params={"check_name": ksi_meta["check_run_name"]},
        )
        response.raise_for_status()
        data = response.json()

    check_runs = data.get("check_runs", [])
    if check_runs:
        return check_runs[0]

    return None
