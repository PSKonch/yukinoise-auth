from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from .conf import KeycloakSettings
from .exceptions import AuthException
from .principal import Principal
from .verifier import TokenVerifier

# Global settings instance (can be overridden)
_settings: KeycloakSettings | None = None


def init_auth(settings: KeycloakSettings) -> None:
    """Initialize authentication with settings.

    Call this function at application startup to set global settings.

    Args:
        settings: Keycloak configuration settings

    Example:
        settings = KeycloakSettings()
        init_auth(settings)
    """
    global _settings
    _settings = settings


def get_settings() -> KeycloakSettings:
    """Get Keycloak settings (dependency).

    Returns:
        KeycloakSettings instance

    Raises:
        RuntimeError: If init_auth() was not called
    """
    if _settings is None:
        raise RuntimeError(
            "Authentication not initialized. Call init_auth(settings) at startup."
        )
    return _settings


def get_token_verifier(
    settings: Annotated[KeycloakSettings, Depends(get_settings)]
) -> TokenVerifier:
    """Get token verifier instance (dependency).

    Args:
        settings: Keycloak settings from dependency

    Returns:
        TokenVerifier instance
    """
    return TokenVerifier(settings)


def extract_token(request: Request) -> str:
    """Extract JWT token from request Authorization header.

    Args:
        request: FastAPI request

    Returns:
        JWT token string

    Raises:
        HTTPException: If token is missing or malformed
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication header format. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return parts[1]


def get_current_principal(
    token: Annotated[str, Depends(extract_token)],
    verifier: Annotated[TokenVerifier, Depends(get_token_verifier)]
) -> Principal:
    """Get current authenticated principal from JWT token (dependency).

    This is the main dependency to use in your route handlers.

    Args:
        token: JWT token from extract_token dependency
        verifier: Token verifier from get_token_verifier dependency

    Returns:
        Principal representing the authenticated user

    Raises:
        HTTPException: If token is invalid or expired

    Example:
        @app.get("/protected")
        async def protected_route(
            principal: Annotated[Principal, Depends(get_current_principal)]
        ):
            return {"user_id": principal.user_id}
    """
    try:
        payload = verifier.verify_token(token)
        return Principal.from_token(payload)
    except AuthException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def get_optional_principal(request: Request) -> Principal | None:
    """Get principal from request state (set by middleware) or return None.

    Use this for routes where authentication is optional.

    Args:
        request: FastAPI request

    Returns:
        Principal if authenticated, None otherwise

    Example:
        @app.get("/optional")
        async def optional_route(
            principal: Annotated[Principal | None, Depends(get_optional_principal)]
        ):
            if principal:
                return {"user_id": principal.user_id}
            return {"user_id": "anonymous"}
    """
    return getattr(request.state, "principal", None)


def require_realm_role(required_role: str):
    """Create a dependency that requires a specific realm role.

    Args:
        required_role: Role name that user must have

    Returns:
        Dependency function

    Example:
        @app.get("/admin")
        async def admin_route(
            principal: Annotated[Principal, Depends(require_realm_role("admin"))]
        ):
            return {"message": "Admin access granted"}
    """
    def _check_role(
        principal: Annotated[Principal, Depends(get_current_principal)]
    ) -> Principal:
        if not principal.has_realm_role(required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required role: {required_role}"
            )
        return principal

    return _check_role


def require_any_realm_role(*roles: str):
    """Create a dependency that requires any of the specified realm roles.

    Args:
        *roles: Role names (user must have at least one)

    Returns:
        Dependency function

    Example:
        @app.get("/moderator")
        async def moderator_route(
            principal: Annotated[Principal, Depends(require_any_realm_role("admin", "moderator"))]
        ):
            return {"message": "Moderator access granted"}
    """
    def _check_roles(
        principal: Annotated[Principal, Depends(get_current_principal)]
    ) -> Principal:
        if not principal.has_any_realm_role(list(roles)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required roles. Need one of: {', '.join(roles)}"
            )
        return principal

    return _check_roles


def require_all_realm_roles(*roles: str):
    """Create a dependency that requires all specified realm roles.

    Args:
        *roles: Role names (user must have all of them)

    Returns:
        Dependency function

    Example:
        @app.get("/super-admin")
        async def super_admin_route(
            principal: Annotated[Principal, Depends(require_all_realm_roles("admin", "superuser"))]
        ):
            return {"message": "Super admin access granted"}
    """
    def _check_roles(
        principal: Annotated[Principal, Depends(get_current_principal)]
    ) -> Principal:
        if not principal.has_all_realm_roles(list(roles)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required roles. Need all of: {', '.join(roles)}"
            )
        return principal

    return _check_roles


def require_client_role(client_id: str, required_role: str):
    """Create a dependency that requires a specific client role.

    Args:
        client_id: Client ID
        required_role: Role name that user must have for this client

    Returns:
        Dependency function

    Example:
        @app.get("/app-admin")
        async def app_admin_route(
            principal: Annotated[Principal, Depends(require_client_role("my-app", "admin"))]
        ):
            return {"message": "App admin access granted"}
    """
    def _check_role(
        principal: Annotated[Principal, Depends(get_current_principal)]
    ) -> Principal:
        if not principal.has_client_role(client_id, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required client role: {required_role} for client: {client_id}"
            )
        return principal

    return _check_role


def require_group(group_name: str):
    """Create a dependency that requires membership in a specific group.

    Args:
        group_name: Group name/path that user must be member of

    Returns:
        Dependency function

    Example:
        @app.get("/vip")
        async def vip_route(
            principal: Annotated[Principal, Depends(require_group("/vip-users"))]
        ):
            return {"message": "VIP access granted"}
    """
    def _check_group(
        principal: Annotated[Principal, Depends(get_current_principal)]
    ) -> Principal:
        if not principal.in_group(group_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Must be member of group: {group_name}"
            )
        return principal

    return _check_group
