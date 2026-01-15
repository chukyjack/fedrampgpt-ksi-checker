"""GitHub webhook signature verification."""

import hashlib
import hmac
import logging
from typing import Callable

from fastapi import HTTPException, Request

from app.config import get_settings

logger = logging.getLogger(__name__)


def verify_webhook_signature(payload: bytes, signature: str | None) -> bool:
    """Verify GitHub webhook signature.

    Args:
        payload: Raw request body
        signature: X-Hub-Signature-256 header value

    Returns:
        True if signature is valid

    Raises:
        HTTPException: If signature is invalid or missing
    """
    if not signature:
        raise HTTPException(status_code=401, detail="Missing webhook signature")

    settings = get_settings()

    # Compute expected signature
    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    return True


async def get_verified_payload(request: Request) -> dict:
    """Get and verify webhook payload.

    Args:
        request: FastAPI request object

    Returns:
        Parsed JSON payload

    Raises:
        HTTPException: If signature is invalid
    """
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    verify_webhook_signature(body, signature)

    return await request.json()
