"""Configuration settings for YukiNoise Auth library."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class KeycloakSettings(BaseSettings):
    """Keycloak configuration settings.

    These settings can be provided via environment variables or .env file.
    All environment variables should be prefixed with KEYCLOAK_.

    Example:
        KEYCLOAK_SERVER_URL=http://localhost:8080
        KEYCLOAK_REALM=myrealm
        KEYCLOAK_CLIENT_ID=myapp
    """

    model_config = SettingsConfigDict(
        env_prefix="KEYCLOAK_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Keycloak server configuration
    server_url: str
    """Base URL of Keycloak server (e.g., http://localhost:8080)"""

    realm: str
    """Keycloak realm name"""

    client_id: str
    """Client ID for the application"""

    client_secret: str | None = None
    """Client secret (required for confidential clients)"""

    # Token validation settings
    verify_signature: bool = True
    """Whether to verify JWT signature"""

    verify_exp: bool = True
    """Whether to verify token expiration"""

    verify_aud: bool = True
    """Whether to verify token audience"""

    audience: str | None = None
    """Expected audience (defaults to client_id if not specified)"""

    # JWKS settings
    jwks_cache_ttl: int = 3600
    """Time to live for JWKS cache in seconds (default: 1 hour)"""

    # Additional settings
    algorithms: list[str] = ["RS256"]
    """Allowed JWT algorithms"""

    @property
    def jwks_uri(self) -> str:
        """Get JWKS URI for the realm."""
        return f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/certs"

    @property
    def token_endpoint(self) -> str:
        """Get token endpoint for the realm."""
        return f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"

    @property
    def userinfo_endpoint(self) -> str:
        """Get userinfo endpoint for the realm."""
        return f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/userinfo"

    @property
    def expected_audience(self) -> str:
        """Get expected audience (defaults to client_id if not set)."""
        return self.audience or self.client_id
