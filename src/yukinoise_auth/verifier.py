"""JWT token verification for Keycloak tokens."""

from typing import Any

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidTokenError,
)

from .conf import KeycloakSettings
from .exceptions import AuthException, InvalidTokenException, TokenExpiredException
from .jwks import JWKSClient


class TokenVerifier:
    """Verifies JWT tokens issued by Keycloak.

    This class handles token validation including signature verification,
    expiration checks, and audience validation.
    """

    def __init__(self, settings: KeycloakSettings):
        """Initialize token verifier.

        Args:
            settings: Keycloak configuration settings
        """
        self.settings = settings
        self.jwks_client = JWKSClient(settings)

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify and decode a JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            TokenExpiredException: If token has expired
            InvalidTokenException: If token is invalid
            AuthException: For other authentication errors
        """
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key(token)

            # Prepare decode options
            options = {
                "verify_signature": self.settings.verify_signature,
                "verify_exp": self.settings.verify_exp,
                "verify_aud": self.settings.verify_aud,
            }

            # Decode and verify token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.settings.algorithms,
                audience=self.settings.expected_audience if self.settings.verify_aud else None,
                options=options
            )

            return payload

        except ExpiredSignatureError as e:
            raise TokenExpiredException("Token has expired") from e
        except InvalidAudienceError as e:
            raise InvalidTokenException(
                f"Invalid audience. Expected: {self.settings.expected_audience}"
            ) from e
        except DecodeError as e:
            raise InvalidTokenException("Token decode failed") from e
        except InvalidTokenError as e:
            raise InvalidTokenException(f"Invalid token: {str(e)}") from e
        except Exception as e:
            raise AuthException(f"Token verification failed: {str(e)}") from e

    def decode_token_unsafe(self, token: str) -> dict[str, Any]:
        """Decode token without verification (for inspection only).

        Warning: This does not verify the token signature or expiration.
        Use only for debugging or when you need to inspect token contents.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            InvalidTokenException: If token cannot be decoded
        """
        try:
            return jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False}
            )
        except Exception as e:
            raise InvalidTokenException(f"Failed to decode token: {str(e)}") from e

    def get_token_header(self, token: str) -> dict[str, Any]:
        """Get token header without verification.

        Args:
            token: JWT token string

        Returns:
            Token header dictionary

        Raises:
            InvalidTokenException: If token header cannot be decoded
        """
        try:
            return jwt.get_unverified_header(token)
        except Exception as e:
            raise InvalidTokenException(f"Failed to get token header: {str(e)}") from e
