"""FastAPI application for FedRAMP KSI GitHub App.

Handles GitHub webhooks and creates Check Runs based on workflow results.
"""

import logging
import sys
from contextlib import asynccontextmanager
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse

from app.artifacts import find_all_evidence_artifacts, get_all_ksi_evaluation_results
from app.checks import create_check_run, find_existing_check_run, update_check_run
from app.config import get_settings
from app.webhook import get_verified_payload

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    settings = get_settings()
    logger.info(f"Starting {settings.app_name}")
    logger.info(f"Environment: {settings.environment}")
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="FedRAMP KSI GitHub App",
    description="GitHub App for FedRAMP 20x KSI compliance evaluation",
    version="1.1.0",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "app": "FedRAMP KSI GitHub App", "version": "1.1.0"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


async def process_workflow_run(payload: dict[str, Any]) -> None:
    """Process a workflow_run event.

    Called when a workflow run completes. Downloads artifacts and creates Check Runs
    for each KSI found in the workflow artifacts.

    Args:
        payload: Webhook payload
    """
    try:
        action = payload.get("action")
        workflow_run = payload.get("workflow_run", {})
        repository = payload.get("repository", {})
        installation = payload.get("installation", {})

        # Only process completed runs
        if action != "completed":
            logger.debug(f"Ignoring workflow_run action: {action}")
            return

        installation_id = installation.get("id")
        owner = repository.get("owner", {}).get("login")
        repo = repository.get("name")
        run_id = workflow_run.get("id")
        head_sha = workflow_run.get("head_sha")
        run_url = workflow_run.get("html_url")
        workflow_name = workflow_run.get("name", "")

        if not all([installation_id, owner, repo, run_id, head_sha]):
            logger.error("Missing required fields in workflow_run payload")
            return

        logger.info(f"Processing workflow run {run_id} for {owner}/{repo}")

        # Check if this workflow produced any KSI evidence artifacts
        evidence_artifacts = await find_all_evidence_artifacts(installation_id, owner, repo, run_id)
        if not evidence_artifacts:
            logger.info(f"No KSI evidence artifacts found for run {run_id} - skipping")
            return

        logger.info(f"Found {len(evidence_artifacts)} evidence artifact(s)")

        # Get evaluation results for all KSIs
        ksi_results = await get_all_ksi_evaluation_results(installation_id, owner, repo, run_id)

        if not ksi_results:
            logger.error("Could not extract evaluation manifests from artifacts")
            return

        # Process each KSI result
        for result in ksi_results:
            ksi_id = result["ksi_id"]
            artifact_name = result["artifact_name"]
            manifest = result["manifest"]

            # Get status from manifest (handle different structures)
            summary_data = manifest.get("summary", {})
            status = summary_data.get("status") if summary_data else manifest.get("status", "UNKNOWN")
            logger.info(f"{ksi_id} status: {status}")

            # Check for existing check run for this specific KSI
            existing = await find_existing_check_run(
                installation_id, owner, repo, head_sha, ksi_id
            )

            if existing:
                # Update existing check run
                logger.info(f"Updating existing check run {existing.get('id')} for {ksi_id}")
                await update_check_run(
                    installation_id=installation_id,
                    owner=owner,
                    repo=repo,
                    check_run_id=existing["id"],
                    manifest=manifest,
                    artifact_name=artifact_name,
                    run_url=run_url,
                    ksi_id=ksi_id,
                )
            else:
                # Create new check run
                logger.info(f"Creating check run for {ksi_id} on {head_sha}")
                await create_check_run(
                    installation_id=installation_id,
                    owner=owner,
                    repo=repo,
                    head_sha=head_sha,
                    manifest=manifest,
                    artifact_name=artifact_name,
                    run_url=run_url,
                    ksi_id=ksi_id,
                )

        logger.info(f"Successfully processed workflow run {run_id} with {len(ksi_results)} KSI(s)")

    except Exception as e:
        logger.error(f"Error processing workflow run: {e}", exc_info=True)


@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """Handle GitHub webhook events.

    Verifies signature and dispatches to appropriate handler.
    """
    try:
        # Verify signature and get payload
        payload = await get_verified_payload(request)
    except Exception as e:
        logger.error(f"Failed to verify webhook: {e}")
        return JSONResponse(
            content={"status": "error", "message": "Signature verification failed"},
            status_code=401,
        )

    event_type = request.headers.get("X-GitHub-Event", "unknown")
    delivery_id = request.headers.get("X-GitHub-Delivery", "unknown")

    logger.info(f"Received webhook: {event_type} (delivery: {delivery_id})")

    # Handle workflow_run events
    if event_type == "workflow_run":
        # Process in background to return quickly
        background_tasks.add_task(process_workflow_run, payload)
        return JSONResponse(
            content={"status": "accepted", "event": event_type},
            status_code=202,
        )

    # Handle check_suite events (alternative trigger)
    if event_type == "check_suite":
        action = payload.get("action")
        if action == "completed":
            # Could implement check_suite handling here
            logger.debug("check_suite completed event received")

    # Handle ping event (sent when webhook is first configured)
    if event_type == "ping":
        zen = payload.get("zen", "")
        hook_id = payload.get("hook_id", "")
        logger.info(f"Webhook ping received: {zen} (hook_id: {hook_id})")
        return {"status": "pong", "zen": zen}

    return {"status": "ok", "event": event_type}


@app.post("/webhook/github")
async def webhook_github(request: Request, background_tasks: BackgroundTasks):
    """Alternative webhook endpoint for GitHub."""
    return await webhook(request, background_tasks)


def run():
    """Run the application with uvicorn."""
    import uvicorn

    settings = get_settings()
    log_level = settings.log_level.lower()

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        log_level=log_level,
        reload=settings.environment == "development",
    )


if __name__ == "__main__":
    run()
