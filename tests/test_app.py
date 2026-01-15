"""Tests for the GitHub App FastAPI service."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    return Settings(
        github_app_id="12345",
        github_app_private_key="-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
        github_webhook_secret="test-secret",
    )


def sign_payload(payload: dict, secret: str) -> str:
    """Generate webhook signature for payload."""
    body = json.dumps(payload).encode()
    signature = hmac.new(
        secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={signature}"


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_root(self, client):
        """Should return app info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "FedRAMP" in data["app"]

    def test_health(self, client):
        """Should return healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestWebhookEndpoint:
    """Tests for webhook endpoint."""

    def test_rejects_missing_signature(self, client):
        """Should reject requests without signature."""
        response = client.post(
            "/webhook",
            json={"action": "test"},
        )
        assert response.status_code == 401

    def test_rejects_invalid_signature(self, client):
        """Should reject requests with invalid signature."""
        response = client.post(
            "/webhook",
            json={"action": "test"},
            headers={"X-Hub-Signature-256": "sha256=invalid"},
        )
        assert response.status_code == 401

    @patch("app.webhook.get_settings")
    def test_accepts_valid_signature(self, mock_get_settings, client, mock_settings):
        """Should accept requests with valid signature."""
        mock_get_settings.return_value = mock_settings

        payload = {"action": "ping", "zen": "test"}
        signature = sign_payload(payload, mock_settings.github_webhook_secret)

        response = client.post(
            "/webhook",
            content=json.dumps(payload),
            headers={
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "ping",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200

    @patch("app.webhook.get_settings")
    def test_handles_ping_event(self, mock_get_settings, client, mock_settings):
        """Should handle ping events."""
        mock_get_settings.return_value = mock_settings

        payload = {"zen": "Keep it simple", "hook_id": 12345}
        signature = sign_payload(payload, mock_settings.github_webhook_secret)

        response = client.post(
            "/webhook",
            content=json.dumps(payload),
            headers={
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "ping",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pong"
        assert data["zen"] == "Keep it simple"

    @patch("app.main.process_workflow_run")
    @patch("app.webhook.get_settings")
    def test_accepts_workflow_run_event(
        self, mock_get_settings, mock_process, client, mock_settings
    ):
        """Should accept workflow_run events."""
        mock_get_settings.return_value = mock_settings
        mock_process.return_value = None

        payload = {
            "action": "completed",
            "workflow_run": {
                "id": 12345,
                "head_sha": "abc123",
                "html_url": "https://github.com/test/repo/actions/runs/12345",
            },
            "repository": {
                "name": "repo",
                "owner": {"login": "test"},
            },
            "installation": {"id": 67890},
        }
        signature = sign_payload(payload, mock_settings.github_webhook_secret)

        response = client.post(
            "/webhook",
            content=json.dumps(payload),
            headers={
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "workflow_run",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 202
        assert response.json()["status"] == "accepted"


class TestCheckRunSummary:
    """Tests for check run summary generation."""

    def test_builds_summary_for_pass(self):
        """Should build correct summary for PASS status."""
        from app.checks import build_check_run_summary

        manifest = {
            "status": "PASS",
            "reasons": ["All criteria passed."],
            "scope": {
                "repository": "test/repo",
                "commit_sha": "abc1234567890",
                "configuration_surfaces": ["TERRAFORM"],
                "terraform_paths": ["."],
            },
            "process": {
                "workflow_name": "FedRAMP KSI Evidence",
                "workflow_run_id": "12345",
                "trigger_event": "schedule",
                "actor": "github-actions",
            },
            "criteria": [
                {
                    "id": "MLA05-A",
                    "name": "Configuration Surface in Scope",
                    "status": "PASS",
                    "reason": "Terraform detected",
                },
            ],
        }

        summary = build_check_run_summary(manifest, "evidence_ksi-mla-05_abc1234.zip")

        assert "KSI-MLA-05" in summary
        assert "PASS" in summary
        assert "MLA05-A" in summary
        assert "evidence_ksi-mla-05_abc1234.zip" in summary

    def test_builds_summary_for_fail(self):
        """Should build correct summary for FAIL status."""
        from app.checks import build_check_run_summary

        manifest = {
            "status": "FAIL",
            "reasons": ["MLA05-C: Workflow not triggered by schedule."],
            "scope": {
                "repository": "test/repo",
                "commit_sha": "abc1234567890",
                "configuration_surfaces": ["TERRAFORM"],
                "terraform_paths": ["."],
            },
            "process": {
                "workflow_name": "FedRAMP KSI Evidence",
                "workflow_run_id": "12345",
                "trigger_event": "push",
                "actor": "developer",
            },
            "criteria": [
                {
                    "id": "MLA05-C",
                    "name": "Persistent Cycle Configured",
                    "status": "FAIL",
                    "reason": "Not triggered by schedule",
                },
            ],
        }

        summary = build_check_run_summary(manifest)

        assert "FAIL" in summary
        assert "MLA05-C" in summary


class TestStatusMapping:
    """Tests for status to conclusion mapping."""

    def test_status_to_conclusion(self):
        """Should map KSI status to GitHub conclusion correctly."""
        from app.checks import status_to_conclusion

        assert status_to_conclusion("PASS") == "success"
        assert status_to_conclusion("FAIL") == "failure"
        assert status_to_conclusion("ERROR") == "neutral"
        assert status_to_conclusion("UNKNOWN") == "neutral"
