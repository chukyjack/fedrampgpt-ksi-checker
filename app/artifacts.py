"""GitHub artifact download and processing."""

import fnmatch
import io
import json
import zipfile
from typing import Any

import httpx

from app.config import get_settings
from app.github_auth import github_auth


async def list_workflow_run_artifacts(
    installation_id: int,
    owner: str,
    repo: str,
    run_id: int,
) -> list[dict[str, Any]]:
    """List artifacts for a workflow run.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        run_id: Workflow run ID

    Returns:
        List of artifact metadata dicts
    """
    token = await github_auth.get_installation_token(installation_id)
    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.github_api_url}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
            headers=github_auth.get_headers(token),
        )
        response.raise_for_status()
        data = response.json()

    return data.get("artifacts", [])


async def find_evidence_artifact(
    installation_id: int,
    owner: str,
    repo: str,
    run_id: int,
) -> dict[str, Any] | None:
    """Find the KSI evidence artifact in a workflow run.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        run_id: Workflow run ID

    Returns:
        Artifact metadata dict or None if not found
    """
    settings = get_settings()
    artifacts = await list_workflow_run_artifacts(installation_id, owner, repo, run_id)

    # Look for evidence artifact matching pattern
    for artifact in artifacts:
        name = artifact.get("name", "")
        if fnmatch.fnmatch(name, settings.artifact_name_pattern):
            return artifact

    return None


async def find_all_evidence_artifacts(
    installation_id: int,
    owner: str,
    repo: str,
    run_id: int,
) -> list[dict[str, Any]]:
    """Find all KSI evidence artifacts in a workflow run.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        run_id: Workflow run ID

    Returns:
        List of artifact metadata dicts matching KSI evidence patterns
    """
    artifacts = await list_workflow_run_artifacts(installation_id, owner, repo, run_id)

    # Match evidence artifacts for any KSI (evidence_ksi-xxx-xx_*)
    evidence_artifacts = []
    for artifact in artifacts:
        name = artifact.get("name", "")
        if fnmatch.fnmatch(name, "evidence_ksi-*_*"):
            evidence_artifacts.append(artifact)

    return evidence_artifacts


async def find_results_artifact(
    installation_id: int,
    owner: str,
    repo: str,
    run_id: int,
) -> dict[str, Any] | None:
    """Find the results summary artifact in a workflow run.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        run_id: Workflow run ID

    Returns:
        Artifact metadata dict or None if not found
    """
    settings = get_settings()
    artifacts = await list_workflow_run_artifacts(installation_id, owner, repo, run_id)

    for artifact in artifacts:
        if artifact.get("name") == settings.results_artifact_name:
            return artifact

    return None


async def download_artifact(
    installation_id: int,
    owner: str,
    repo: str,
    artifact_id: int,
) -> bytes:
    """Download an artifact zip file.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        artifact_id: Artifact ID

    Returns:
        Artifact content as bytes
    """
    token = await github_auth.get_installation_token(installation_id)
    settings = get_settings()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(
            f"{settings.github_api_url}/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip",
            headers=github_auth.get_headers(token),
        )
        response.raise_for_status()

    return response.content


async def extract_evaluation_manifest(artifact_content: bytes) -> dict[str, Any] | None:
    """Extract evaluation_manifest.json from an artifact zip.

    Args:
        artifact_content: Artifact zip content as bytes

    Returns:
        Parsed evaluation manifest or None if not found
    """
    try:
        with zipfile.ZipFile(io.BytesIO(artifact_content)) as zf:
            # Look for evaluation_manifest.json
            for name in zf.namelist():
                if name.endswith("evaluation_manifest.json"):
                    with zf.open(name) as f:
                        return json.load(f)
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError):
        pass

    return None


async def extract_results_summary(artifact_content: bytes) -> dict[str, Any] | None:
    """Extract results.json from an artifact zip.

    Args:
        artifact_content: Artifact zip content as bytes

    Returns:
        Parsed results summary or None if not found
    """
    try:
        with zipfile.ZipFile(io.BytesIO(artifact_content)) as zf:
            # Look for results.json
            for name in zf.namelist():
                if name.endswith("results.json"):
                    with zf.open(name) as f:
                        return json.load(f)
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError):
        pass

    return None


async def get_evaluation_results(
    installation_id: int,
    owner: str,
    repo: str,
    run_id: int,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Get evaluation results from workflow run artifacts.

    Attempts to get both the full manifest and the quick results summary.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        run_id: Workflow run ID

    Returns:
        Tuple of (evaluation_manifest, results_summary)
    """
    manifest = None
    summary = None

    # Try to get the main evidence artifact
    evidence_artifact = await find_evidence_artifact(installation_id, owner, repo, run_id)
    if evidence_artifact:
        content = await download_artifact(
            installation_id, owner, repo, evidence_artifact["id"]
        )
        manifest = await extract_evaluation_manifest(content)

    # Try to get the results summary artifact
    results_artifact = await find_results_artifact(installation_id, owner, repo, run_id)
    if results_artifact:
        content = await download_artifact(
            installation_id, owner, repo, results_artifact["id"]
        )
        summary = await extract_results_summary(content)

    return manifest, summary


def extract_ksi_id_from_artifact_name(artifact_name: str) -> str | None:
    """Extract KSI ID from artifact name.

    Args:
        artifact_name: Artifact name like 'evidence_ksi-mla-05_abc1234_...'

    Returns:
        KSI ID like 'KSI-MLA-05' or None if not found
    """
    # Pattern: evidence_ksi-xxx-yy_sha_timestamp
    if not artifact_name.startswith("evidence_ksi-"):
        return None

    parts = artifact_name.split("_")
    if len(parts) < 2:
        return None

    # parts[1] is like 'ksi-mla-05' or 'ksi-cna-01'
    ksi_part = parts[1]  # e.g., 'ksi-mla-05'
    # Convert to uppercase: 'KSI-MLA-05'
    return ksi_part.upper()


async def get_all_ksi_evaluation_results(
    installation_id: int,
    owner: str,
    repo: str,
    run_id: int,
) -> list[dict[str, Any]]:
    """Get evaluation results for all KSIs from workflow run artifacts.

    Args:
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        run_id: Workflow run ID

    Returns:
        List of dicts with 'ksi_id', 'artifact_name', 'artifact_id', and 'manifest'
    """
    results = []

    # Find all evidence artifacts
    artifacts = await find_all_evidence_artifacts(installation_id, owner, repo, run_id)

    for artifact in artifacts:
        artifact_name = artifact.get("name", "")
        artifact_id = artifact.get("id")
        ksi_id = extract_ksi_id_from_artifact_name(artifact_name)

        if not ksi_id:
            continue

        # Download and extract manifest
        content = await download_artifact(installation_id, owner, repo, artifact_id)
        manifest = await extract_evaluation_manifest(content)

        if manifest:
            results.append({
                "ksi_id": ksi_id,
                "artifact_name": artifact_name,
                "artifact_id": artifact_id,
                "manifest": manifest,
            })

    return results
