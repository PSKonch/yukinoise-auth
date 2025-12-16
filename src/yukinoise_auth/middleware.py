"""FastAPI middleware for automatic JWT token verification."""

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .conf import KeycloakSettings
from .exceptions import AuthException
from .principal import Principal
from .verifier import TokenVerifier


class KeycloakAuthMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic JWT token verification in FastAPI.

    This middleware automatically extracts and verifies JWT tokens from
    Authorization headers and attaches the Principal to the request state.

    Example:
        app = FastAPI()
        settings = KeycloakSettings()
        app.add_middleware(
            KeycloakAuthMiddleware,
            settings=settings,
            exclude_paths=["/health", "/docs"]
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        settings: KeycloakSettings,
        exclude_paths: list[str] | None = None,
        optional_paths: list[str] | None = None,
    ):
        """Initialize middleware.

        Args:
            app: FastAPI application
            settings: Keycloak configuration settings
            exclude_paths: Paths to exclude from authentication (no token required)
            optional_paths: Paths where authentication is optional (token verified if present)
        """
        super().__init__(app)
        self.settings = settings
        self.verifier = TokenVerifier(settings)
        self.exclude_paths = set(exclude_paths or [])
        self.optional_paths = set(optional_paths or [])

    def _should_exclude(self, path: str) -> bool:
        """Check if path should be excluded from authentication."""
        return any(path.startswith(excluded) for excluded in self.exclude_paths)

    def _is_optional(self, path: str) -> bool:
        """Check if authentication is optional for this path."""
        return any(path.startswith(optional) for optional in self.optional_paths)

    def _extract_token(self, request: Request) -> str | None:
        """Extract JWT token from Authorization header.

        Args:
            request: FastAPI request

        Returns:
            JWT token string or None if not present
        """
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None

        # Handle "Bearer <token>" format
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None

        return parts[1]

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Process the request and verify JWT token.

        Args:
            request: FastAPI request
            call_next: Next middleware/handler in chain

        Returns:
            Response from next handler
        """
        path = request.url.path

        # Skip authentication for excluded paths
        if self._should_exclude(path):
            return await call_next(request)

        # Extract token
        token = self._extract_token(request)

        # Handle optional authentication
        if self._is_optional(path):
            if token:
                try:
                    payload = self.verifier.verify_token(token)
                    principal = Principal.from_token(payload)
                    request.state.principal = principal
                    request.state.authenticated = True
                except AuthException:
                    # Token is invalid but authentication is optional
                    request.state.principal = None
                    request.state.authenticated = False
            else:
                request.state.principal = None
                request.state.authenticated = False

            return await call_next(request)

        # Required authentication
        if not token:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing authentication token"}
            )

        try:
            # Verify token
            payload = self.verifier.verify_token(token)
            principal = Principal.from_token(payload)

            # Attach principal to request state
            request.state.principal = principal
            request.state.authenticated = True

            return await call_next(request)

        except AuthException as e:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.message}
            )
