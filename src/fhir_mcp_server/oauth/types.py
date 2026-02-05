# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

import base64
import json
import logging

from typing import Any, Dict, Literal
from pydantic import AnyHttpUrl, BaseModel, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class ServerConfigs(BaseSettings):
    """Contains environment configurations of the MCP server."""

    model_config = SettingsConfigDict(
        env_prefix="FHIR_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # MCP Server settings
    mcp_host: str = "localhost"
    mcp_port: int = 8000
    mcp_server_url: str | None = None
    mcp_request_timeout: int = 30  # in secs

    # FHIR settings
    server_client_id: str = ""
    server_client_secret: str = ""
    server_scopes: str = ""
    server_base_url: str = ""
    server_access_token: str | None = None
    server_disable_authorization: bool = False

    # Authentication settings
    server_auth_type: Literal["oauth", "basic", "token", "none"] = "oauth"
    server_username: str = ""
    server_password: str = ""

    # Read-only mode
    server_read_only: bool = False

    def callback_url(
        self, server_url: str, suffix: str = "/oauth/callback"
    ) -> AnyHttpUrl:
        return AnyHttpUrl(f"{server_url.rstrip('/')}{suffix}")

    @property
    def discovery_url(self) -> str:
        return f"{self.server_base_url.rstrip('/')}/.well-known/smart-configuration"

    @property
    def metadata_url(self) -> str:
        return f"{self.server_base_url.rstrip('/')}/metadata?_format=json"

    @property
    def scopes(self) -> list[str]:
        # If the raw value is a string, split on empty spaces
        if isinstance(self.server_scopes, str):
            return [
                scope.strip()
                for scope in self.server_scopes.split(" ")
                if scope.strip()
            ]
        return [self.server_scopes]

    @property
    def effective_server_url(self) -> str:
        return self.mcp_server_url or f"http://{self.mcp_host}:{self.mcp_port}"

    @property
    def effective_auth_type(self) -> str:
        """
        Determine the effective authentication type based on configuration.
        Priority: disable_authorization > auth_type setting
        """
        if self.server_disable_authorization:
            return "none"
        return self.server_auth_type

    def get_basic_auth_header(self) -> str | None:
        """
        Generate the Basic Authentication header value.

        Returns:
            Base64 encoded 'username:password' string, or None if credentials are missing.
        """
        if not self.server_username or not self.server_password:
            logger.warning("Basic auth credentials are incomplete.")
            return None

        credentials = f"{self.server_username}:{self.server_password}"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        return encoded

    @field_validator('server_auth_type')
    @classmethod
    def validate_auth_type(cls, v: str, info) -> str:
        """Validate auth_type and log warnings for missing credentials."""
        # Note: info.data may not have all fields yet during validation
        # We'll do comprehensive validation in __init__
        return v

    def __init__(self, **data):
        """Initialize settings with values from environment variables"""
        super().__init__(**data)

        # Validate configuration based on auth type
        if self.effective_auth_type == "basic":
            if not self.server_username or not self.server_password:
                logger.warning(
                    "Basic authentication is selected but username or password is missing. "
                    "Set FHIR_SERVER_USERNAME and FHIR_SERVER_PASSWORD environment variables."
                )
        elif self.effective_auth_type == "token":
            if not self.server_access_token:
                logger.warning(
                    "Token authentication is selected but FHIR_SERVER_ACCESS_TOKEN is not set."
                )
        elif self.effective_auth_type == "oauth":
            if not self.server_client_id or not self.server_client_secret:
                logger.warning(
                    "OAuth authentication is selected but client credentials are incomplete. "
                    "Set FHIR_SERVER_CLIENT_ID and FHIR_SERVER_CLIENT_SECRET environment variables."
                )


class OAuthMetadata(BaseModel):
    """
    OAuth 2.0 Authorization Server Metadata.
    """

    issuer: AnyHttpUrl
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    registration_endpoint: AnyHttpUrl | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str]
    response_modes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None
    token_endpoint_auth_signing_alg_values_supported: list[str] | None = None
    service_documentation: AnyHttpUrl | None = None
    ui_locales_supported: list[str] | None = None
    op_policy_uri: AnyHttpUrl | None = None
    op_tos_uri: AnyHttpUrl | None = None
    revocation_endpoint: AnyHttpUrl | None = None
    revocation_endpoint_auth_methods_supported: list[str] | None = None
    revocation_endpoint_auth_signing_alg_values_supported: None = None
    introspection_endpoint: AnyHttpUrl | None = None
    introspection_endpoint_auth_methods_supported: list[str] | None = None
    introspection_endpoint_auth_signing_alg_values_supported: None = None
    code_challenge_methods_supported: list[str] | None = None


class OAuthToken(BaseModel):
    """
    OAuth 2.0 token with metadata.
    """

    access_token: str
    token_type: str
    expires_in: int | None = None
    scope: str | None = None
    refresh_token: str | None = None
    expires_at: float | None = None
    id_token: str | None = None
    client_id: str | None = None

    @property
    def scopes(self) -> list[str]:
        return self.scope.split(" ") if self.scope else []

    def get_id_token(self) -> "IDToken | None":
        """
        Parse the id_token and return an IDToken object.

        Returns:
            An IDToken instance populated from the JWT payload or None if parsing fails.
        """
        payload: Dict[str, Any] | None = (
            decode_jws(self.id_token) if self.id_token else None
        )
        if not payload:
            return None

        return IDToken.model_validate(payload)


class AuthorizationCode(BaseModel):
    code: str
    scopes: list[str]
    expires_at: float
    client_id: str
    code_verifier: str
    code_challenge: str
    redirect_uri: AnyHttpUrl
    redirect_uri_provided_explicitly: bool


class IDToken(BaseModel):
    fhirUser: str | None = None

    def parse_fhir_user(self) -> tuple[str, str] | None:
        """
        Parse the fhirUser URL to extract resource type and resource ID.

        The fhirUser URL MAY be absolute (e.g., https://ehr.example.org/Practitioner/123),
        or it MAY be relative to the FHIR server base URL (e.g., Practitioner/123).

        Returns:
            A tuple of (resource_type, resource_id) if fhirUser is valid,
            None otherwise.
        """
        if not self.fhirUser:
            return None

        logger.debug(f"Parsing fhirUser: {self.fhirUser}")
        parts: list[str] = self.fhirUser.rstrip('/').split("/")

        if len(parts) < 2:
            return None

        return parts[len(parts) - 2], parts[len(parts) - 1]

    @property
    def resource_type(self) -> str | None:
        """Get the FHIR resource type from fhirUser URL."""
        parsed = self.parse_fhir_user()
        return parsed[0] if parsed else None

    @property
    def resource_id(self) -> str | None:
        """Get the FHIR resource ID from fhirUser URL."""
        parsed = self.parse_fhir_user()
        return parsed[1] if parsed else None


def decode_jws(jws: str) -> Dict[str, Any] | None:
    """
    Decode the provided JWS payload.

    Returns:
        The decoded JWS payload as a dictionary.
    """
    try:
        parts: list[str] = jws.split(".")
        if len(parts) != 3:
            logger.debug(
                f"Decoding JWS failed: Invalid JWS format, expected 3 parts but got {len(parts)}: {jws}"
            )
            return None

        padded: str = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded: bytes = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)

    except Exception as e:
        logger.exception("Error decoding JWS token. Caused by, ", exc_info=e)
        return None
