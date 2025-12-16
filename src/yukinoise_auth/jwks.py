"""JWKS (JSON Web Key Set) client for retrieving and caching public keys."""

import time
from typing import Any

import httpx
from jwt import PyJWKClient

from .conf import KeycloakSettings
from .exceptions import KeycloakConnectionException


class JWKSClient:
    """Client for fetching and caching JWKS from Keycloak.

    This client retrieves public keys from Keycloak's JWKS endpoint
    and caches them for efficient token verification.
    """

    def __init__(self, settings: KeycloakSettings):
        """Initialize JWKS client.

        Args:
            settings: Keycloak configuration settings
        """
        self.settings = settings
        self._jwk_client: PyJWKClient | None = None
        self._cache_time: float = 0
        self._cache_ttl = settings.jwks_cache_ttl

    @property
    def jwk_client(self) -> PyJWKClient:
        """Get or create PyJWKClient instance with caching."""
        current_time = time.time()

        # Check if cache is expired or client doesn't exist
        if self._jwk_client is None or (current_time - self._cache_time) > self._cache_ttl:
            try:
                self._jwk_client = PyJWKClient(
                    self.settings.jwks_uri,
                    cache_keys=True,
                    max_cached_keys=16,
                    cache_jwk_set=True,
                    lifespan=self._cache_ttl
                )
                self._cache_time = current_time
            except Exception as e:
                raise KeycloakConnectionException(
                    f"Failed to initialize JWKS client: {str(e)}"
                ) from e

        return self._jwk_client

    def get_signing_key(self, token: str) -> Any:
        """Get signing key for a token.

        Args:
            token: JWT token string

        Returns:
            Signing key for the token

        Raises:
            KeycloakConnectionException: If failed to retrieve signing key
        """
        try:
            return self.jwk_client.get_signing_key_from_jwt(token)
        except Exception as e:
            raise KeycloakConnectionException(
                f"Failed to get signing key: {str(e)}"
            ) from e

    async def fetch_jwks(self) -> dict[str, Any]:
        """Fetch JWKS directly from Keycloak (for manual inspection).

        Returns:
            JWKS dictionary

        Raises:
            KeycloakConnectionException: If failed to fetch JWKS
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.settings.jwks_uri, timeout=10.0)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            raise KeycloakConnectionException(
                f"Failed to fetch JWKS: {str(e)}"
            ) from e

    def clear_cache(self) -> None:
        """Clear the JWKS cache."""
        self._jwk_client = None
        self._cache_time = 0
