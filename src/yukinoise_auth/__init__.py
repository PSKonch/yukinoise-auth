"""YukiNoise Auth - Keycloak authentication library for FastAPI microservices.

This library provides simple and efficient Keycloak authentication integration
for Python FastAPI applications with support for JWT token verification,
role-based access control, and middleware.
"""

from .conf import KeycloakSettings
from .exceptions import (
    AuthException,
    InsufficientPermissionsException,
    InvalidTokenException,
    KeycloakConnectionException,
    MissingTokenException,
    TokenExpiredException,
)
from .fastapi import (
    extract_token,
    get_current_principal,
    get_optional_principal,
    get_settings,
    get_token_verifier,
    init_auth,
    require_all_realm_roles,
    require_any_realm_role,
    require_client_role,
    require_group,
    require_realm_role,
)
from .jwks import JWKSClient
from .middleware import KeycloakAuthMiddleware
from .principal import Principal
from .verifier import TokenVerifier

__version__ = "0.1.0"
__author__ = "PSK"

__all__ = [
    # Configuration
    "KeycloakSettings",

    # Exceptions
    "AuthException",
    "TokenExpiredException",
    "InvalidTokenException",
    "MissingTokenException",
    "InsufficientPermissionsException",
    "KeycloakConnectionException",

    # Core classes
    "Principal",
    "TokenVerifier",
    "JWKSClient",
    "KeycloakAuthMiddleware",

    # FastAPI integration
    "init_auth",
    "get_settings",
    "get_token_verifier",
    "extract_token",
    "get_current_principal",
    "get_optional_principal",
    "require_realm_role",
    "require_any_realm_role",
    "require_all_realm_roles",
    "require_client_role",
    "require_group",
]
