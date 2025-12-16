"""Custom exceptions for YukiNoise Auth library."""


class AuthException(Exception):
    """Base exception for authentication errors."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class TokenExpiredException(AuthException):
    """Raised when JWT token has expired."""

    def __init__(self, message: str = "Token has expired"):
        super().__init__(message, status_code=401)


class InvalidTokenException(AuthException):
    """Raised when JWT token is invalid."""

    def __init__(self, message: str = "Invalid token"):
        super().__init__(message, status_code=401)


class MissingTokenException(AuthException):
    """Raised when JWT token is missing."""

    def __init__(self, message: str = "Missing authentication token"):
        super().__init__(message, status_code=401)


class InsufficientPermissionsException(AuthException):
    """Raised when user doesn't have required permissions."""

    def __init__(self, message: str = "Insufficient permissions", required_roles: list[str] | None = None):
        self.required_roles = required_roles or []
        super().__init__(message, status_code=403)


class KeycloakConnectionException(AuthException):
    """Raised when connection to Keycloak fails."""

    def __init__(self, message: str = "Failed to connect to Keycloak"):
        super().__init__(message, status_code=503)
