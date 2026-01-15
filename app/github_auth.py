"""GitHub App authentication utilities."""

import base64
import time
from pathlib import Path
from typing import Any

import httpx
import jwt

from app.config import get_settings


class GitHubAppAuth:
    """Handles GitHub App authentication and token management."""

    def __init__(self) -> None:
        """Initialize the auth handler."""
        self.settings = get_settings()
        self._installation_tokens: dict[int, tuple[str, float]] = {}

    def _generate_jwt(self) -> str:
        """Generate a JWT for GitHub App authentication.

        Returns:
            JWT token string
        """
        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued 60 seconds ago to account for clock drift
            "exp": now + (10 * 60),  # Expires in 10 minutes
            "iss": self.settings.github_app_id,
        }

        # Handle private key (may be PEM content, base64-encoded, or file path)
        private_key = self.settings.github_app_private_key

        if private_key.startswith("-----BEGIN"):
            # Direct PEM content
            key = private_key
        elif len(private_key) < 256 and Path(private_key).exists():
            # File path (only check if short enough to be a path)
            with open(private_key, "r") as f:
                key = f.read()
        else:
            # Try base64 decoding (common for environment variables)
            try:
                decoded = base64.b64decode(private_key).decode("utf-8")
                if decoded.startswith("-----BEGIN"):
                    key = decoded
                else:
                    raise ValueError("Decoded value is not a PEM key")
            except Exception:
                raise ValueError(
                    "GITHUB_APP_PRIVATE_KEY must be PEM content, a file path, or base64-encoded PEM"
                )

        return jwt.encode(payload, key, algorithm="RS256")

    async def get_installation_token(self, installation_id: int) -> str:
        """Get an installation access token.

        Caches tokens until they're close to expiration.

        Args:
            installation_id: GitHub App installation ID

        Returns:
            Installation access token
        """
        # Check cache
        if installation_id in self._installation_tokens:
            token, expires_at = self._installation_tokens[installation_id]
            if time.time() < expires_at - 300:  # 5 minute buffer
                return token

        # Generate new token
        jwt_token = self._generate_jwt()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.settings.github_api_url}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {jwt_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
            data = response.json()

        token = data["token"]
        # Parse expiration time (GitHub returns ISO 8601)
        expires_at = time.time() + 3600  # Default to 1 hour

        self._installation_tokens[installation_id] = (token, expires_at)
        return token

    def get_headers(self, token: str) -> dict[str, str]:
        """Get standard headers for GitHub API requests.

        Args:
            token: Access token (installation or JWT)

        Returns:
            Headers dict
        """
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }


# Global auth instance
github_auth = GitHubAppAuth()
