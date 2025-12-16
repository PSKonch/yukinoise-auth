"""Principal (user) representation from JWT token."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Principal:
    """Represents an authenticated user/principal from JWT token.

    This class contains all relevant information about the authenticated user
    extracted from the JWT token payload.
    """

    # Standard JWT claims
    sub: str
    """Subject - unique identifier of the user (user ID)"""

    email: str | None = None
    """User's email address"""

    preferred_username: str | None = None
    """User's preferred username"""

    name: str | None = None
    """User's full name"""

    given_name: str | None = None
    """User's given (first) name"""

    family_name: str | None = None
    """User's family (last) name"""

    # Keycloak specific claims
    realm_access: dict[str, Any] = field(default_factory=dict)
    """Realm-level access roles and permissions"""

    resource_access: dict[str, Any] = field(default_factory=dict)
    """Client/resource-level access roles and permissions"""

    groups: list[str] = field(default_factory=list)
    """User's group memberships"""

    # Token metadata
    iss: str | None = None
    """Issuer - who issued the token"""

    aud: str | list[str] | None = None
    """Audience - who the token is intended for"""

    exp: int | None = None
    """Expiration time (Unix timestamp)"""

    iat: int | None = None
    """Issued at time (Unix timestamp)"""

    # Raw token data
    raw_token: dict[str, Any] = field(default_factory=dict)
    """Complete raw token payload for custom claims"""

    @classmethod
    def from_token(cls, token_payload: dict[str, Any]) -> "Principal":
        """Create Principal from decoded JWT token payload.

        Args:
            token_payload: Decoded JWT token payload dictionary

        Returns:
            Principal instance
        """
        # Extract realm roles
        realm_access = token_payload.get("realm_access", {})

        # Extract resource/client roles
        resource_access = token_payload.get("resource_access", {})

        # Extract groups
        groups = token_payload.get("groups", [])

        return cls(
            sub=token_payload.get("sub", ""),
            email=token_payload.get("email"),
            preferred_username=token_payload.get("preferred_username"),
            name=token_payload.get("name"),
            given_name=token_payload.get("given_name"),
            family_name=token_payload.get("family_name"),
            realm_access=realm_access,
            resource_access=resource_access,
            groups=groups,
            iss=token_payload.get("iss"),
            aud=token_payload.get("aud"),
            exp=token_payload.get("exp"),
            iat=token_payload.get("iat"),
            raw_token=token_payload
        )

    @property
    def user_id(self) -> str:
        """Get user ID (alias for sub)."""
        return self.sub

    @property
    def username(self) -> str:
        """Get username (preferred_username or email or sub)."""
        return self.preferred_username or self.email or self.sub

    @property
    def realm_roles(self) -> list[str]:
        """Get list of realm-level roles."""
        return self.realm_access.get("roles", [])

    def get_client_roles(self, client_id: str) -> list[str]:
        """Get list of roles for a specific client.

        Args:
            client_id: Client ID to get roles for

        Returns:
            List of role names
        """
        client_access = self.resource_access.get(client_id, {})
        return client_access.get("roles", [])

    def has_realm_role(self, role: str) -> bool:
        """Check if user has a specific realm role.

        Args:
            role: Role name to check

        Returns:
            True if user has the role, False otherwise
        """
        return role in self.realm_roles

    def has_client_role(self, client_id: str, role: str) -> bool:
        """Check if user has a specific client role.

        Args:
            client_id: Client ID
            role: Role name to check

        Returns:
            True if user has the role, False otherwise
        """
        return role in self.get_client_roles(client_id)

    def has_any_realm_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified realm roles.

        Args:
            roles: List of role names to check

        Returns:
            True if user has at least one of the roles, False otherwise
        """
        return any(role in self.realm_roles for role in roles)

    def has_all_realm_roles(self, roles: list[str]) -> bool:
        """Check if user has all of the specified realm roles.

        Args:
            roles: List of role names to check

        Returns:
            True if user has all roles, False otherwise
        """
        return all(role in self.realm_roles for role in roles)

    def in_group(self, group: str) -> bool:
        """Check if user is in a specific group.

        Args:
            group: Group name/path to check

        Returns:
            True if user is in the group, False otherwise
        """
        return group in self.groups

    def get_custom_claim(self, claim_name: str, default: Any = None) -> Any:
        """Get a custom claim from the raw token.

        Args:
            claim_name: Name of the claim
            default: Default value if claim doesn't exist

        Returns:
            Claim value or default
        """
        return self.raw_token.get(claim_name, default)
