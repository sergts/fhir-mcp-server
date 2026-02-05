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

import pytest
import os
from unittest.mock import patch
from pydantic import AnyHttpUrl, ValidationError
from fhir_mcp_server.oauth.types import (
    ServerConfigs,
    OAuthMetadata,
    OAuthToken,
    AuthorizationCode,
)


class TestServerConfigs:
    """Test the ServerConfigs class."""

    def test_default_config(self):
        """Test default server configuration."""
        # Use empty environment and mock file loading to avoid loading existing config
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            
            assert config.mcp_host == "localhost"
            assert config.mcp_port == 8000
            assert config.mcp_server_url is None
            assert config.server_client_id == ""
            assert config.server_client_secret == ""
            assert config.server_scopes == ""
            assert config.server_base_url == ""
            assert config.mcp_request_timeout == 30
            assert config.server_access_token is None

    def test_effective_server_url_default(self):
        """Test effective server URL with default values."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.effective_server_url == "http://localhost:8000"

    def test_effective_server_url_custom_host_port(self):
        """Test effective server URL with custom host and port."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(mcp_host="0.0.0.0", mcp_port=9000, _env_file=None)
            assert config.effective_server_url == "http://0.0.0.0:9000"

    def test_effective_server_url_explicit(self):
        """Test effective server URL with explicit server_url."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(mcp_server_url="https://my-server.com", _env_file=None)
            assert config.effective_server_url == "https://my-server.com"

    def test_config_with_server_values(self):
        """Test server configuration with server values."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                server_client_id="test_client",
                server_base_url="https://example.com/fhir",
                mcp_request_timeout=120,
                _env_file=None
            )

            assert config.server_client_id == "test_client"
            assert config.server_base_url == "https://example.com/fhir"
            assert config.mcp_request_timeout == 120

    def test_callback_url_basic(self):
        """Test callback URL generation."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            callback_url = config.callback_url("https://example.com:8000")
            assert str(callback_url) == "https://example.com:8000/oauth/callback"

    def test_callback_url_custom_suffix(self):
        """Test callback URL generation with custom suffix."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            callback_url = config.callback_url("https://example.com:8000", "/custom/fhir")
            assert str(callback_url) == "https://example.com:8000/custom/fhir"

    def test_discovery_url_property(self):
        """Test discovery URL property."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_base_url="https://custom.fhir.org/R4", _env_file=None)
            assert (
                config.discovery_url
                == "https://custom.fhir.org/R4/.well-known/smart-configuration"
            )

    def test_discovery_url_with_trailing_slash(self):
        """Test discovery URL property with trailing slash."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_base_url="https://custom.fhir.org/R4/", _env_file=None)
            assert (
                config.discovery_url
                == "https://custom.fhir.org/R4/.well-known/smart-configuration"
            )

    def test_metadata_url_property(self):
        """Test metadata URL property."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_base_url="https://custom.fhir.org/R4", _env_file=None)
            assert config.metadata_url == "https://custom.fhir.org/R4/metadata?_format=json"

    def test_metadata_url_with_trailing_slash(self):
        """Test metadata URL property with trailing slash."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_base_url="https://custom.fhir.org/R4/", _env_file=None)
            assert config.metadata_url == "https://custom.fhir.org/R4/metadata?_format=json"

    def test_scopes_property_with_string(self):
        """Test scopes property with string scope."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_scopes="read write admin", _env_file=None)
            assert config.scopes == ["read", "write", "admin"]

    def test_scopes_property_empty(self):
        """Test scopes property with empty scope."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_scopes="", _env_file=None)
            assert config.scopes == []

    def test_scopes_property_with_extra_spaces(self):
        """Test scopes property with extra spaces."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_scopes="  read   write   admin  ", _env_file=None)
            assert config.scopes == ["read", "write", "admin"]


class TestOAuthMetadata:
    """Test the OAuthMetadata class."""

    def test_basic_metadata(self):
        """Test basic OAuth metadata."""
        metadata = OAuthMetadata(
            issuer=AnyHttpUrl("https://example.com"),
            authorization_endpoint=AnyHttpUrl("https://example.com/auth"),
            token_endpoint=AnyHttpUrl("https://example.com/token"),
            response_types_supported=["code"],
        )
        # URLs get normalized by pydantic - trailing slash may be added
        assert str(metadata.issuer).rstrip("/") == "https://example.com"
        assert str(metadata.authorization_endpoint) == "https://example.com/auth"
        assert str(metadata.token_endpoint) == "https://example.com/token"
        assert metadata.response_types_supported == ["code"]

    def test_metadata_with_optional_fields(self):
        """Test OAuth metadata with optional fields."""
        metadata = OAuthMetadata(
            issuer=AnyHttpUrl("https://example.com"),
            authorization_endpoint=AnyHttpUrl("https://example.com/auth"),
            token_endpoint=AnyHttpUrl("https://example.com/token"),
            response_types_supported=["code"],
            scopes_supported=["read", "write"],
            grant_types_supported=["authorization_code"],
            code_challenge_methods_supported=["S256"],
        )
        assert metadata.scopes_supported == ["read", "write"]
        assert metadata.grant_types_supported == ["authorization_code"]
        assert metadata.code_challenge_methods_supported == ["S256"]

    def test_metadata_validation_error(self):
        """Test OAuth metadata validation error."""
        with pytest.raises(ValidationError):
            OAuthMetadata(
                # Missing required fields
                issuer="https://example.com"
            ) # type: ignore


class TestOAuthToken:
    """Test the OAuthToken class."""

    def test_basic_token(self):
        """Test basic OAuth token."""
        token = OAuthToken(access_token="test_access_token", token_type="Bearer")
        assert token.access_token == "test_access_token"
        assert token.token_type == "Bearer"
        assert token.expires_in is None
        assert token.scope is None
        assert token.refresh_token is None

    def test_token_with_all_fields(self):
        """Test OAuth token with all fields."""
        token = OAuthToken(
            access_token="test_access_token",
            token_type="Bearer",
            expires_in=3600,
            scope="read write",
            refresh_token="test_refresh_token",
            expires_at=1234567890.0,
        )
        assert token.access_token == "test_access_token"
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600
        assert token.scope == "read write"
        assert token.refresh_token == "test_refresh_token"
        assert token.expires_at == 1234567890.0

    def test_scopes_property_with_scope(self):
        """Test scopes property with scope string."""
        token = OAuthToken(
            access_token="test_token", token_type="Bearer", scope="read write admin"
        )
        assert token.scopes == ["read", "write", "admin"]

    def test_scopes_property_no_scope(self):
        """Test scopes property without scope."""
        token = OAuthToken(access_token="test_token", token_type="Bearer")
        assert token.scopes == []

    def test_scopes_property_empty_scope(self):
        """Test scopes property with empty scope."""
        token = OAuthToken(access_token="test_token", token_type="Bearer", scope="")
        # Empty scope results in empty list, not list with empty string
        assert token.scopes == []


class TestAuthorizationCode:
    """Test the AuthorizationCode class."""

    def test_basic_authorization_code(self):
        """Test basic authorization code."""
        auth_code = AuthorizationCode(
            code="test_code",
            scopes=["read", "write"],
            expires_at=1234567890.0,
            client_id="test_client",
            code_verifier="test_verifier",
            code_challenge="test_challenge",
            redirect_uri=AnyHttpUrl("https://example.com/callback"),
            redirect_uri_provided_explicitly=True,
        )

        assert auth_code.code == "test_code"
        assert auth_code.scopes == ["read", "write"]
        assert auth_code.expires_at == 1234567890.0
        assert auth_code.client_id == "test_client"
        assert auth_code.code_verifier == "test_verifier"
        assert auth_code.code_challenge == "test_challenge"
        assert str(auth_code.redirect_uri) == "https://example.com/callback"
        assert auth_code.redirect_uri_provided_explicitly is True

    def test_authorization_code_validation_error(self):
        """Test authorization code validation error."""
        with pytest.raises(ValidationError):
            AuthorizationCode(
                # Missing required fields
                code="test_code"
            ) # type: ignore



class TestBasicAuthentication:
    """Test basic authentication functionality in ServerConfigs."""

    def test_basic_auth_type_default(self):
        """Test that default auth type is oauth."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.server_auth_type == "oauth"

    def test_basic_auth_type_setting(self):
        """Test setting auth type to basic."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_auth_type="basic", _env_file=None)
            assert config.server_auth_type == "basic"

    def test_basic_auth_credentials(self):
        """Test basic auth username and password."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                server_auth_type="basic",
                server_username="testuser",
                server_password="testpass",
                _env_file=None
            )
            assert config.server_username == "testuser"
            assert config.server_password == "testpass"

    def test_get_basic_auth_header(self):
        """Test basic auth header generation."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                server_username="testuser",
                server_password="testpass",
                _env_file=None
            )
            header = config.get_basic_auth_header()
            assert header is not None
            # testuser:testpass in base64 is dGVzdHVzZXI6dGVzdHBhc3M=
            assert header == "dGVzdHVzZXI6dGVzdHBhc3M="

    def test_get_basic_auth_header_missing_username(self):
        """Test basic auth header with missing username."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                server_password="testpass",
                _env_file=None
            )
            header = config.get_basic_auth_header()
            assert header is None

    def test_get_basic_auth_header_missing_password(self):
        """Test basic auth header with missing password."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                server_username="testuser",
                _env_file=None
            )
            header = config.get_basic_auth_header()
            assert header is None

    def test_get_basic_auth_header_empty_credentials(self):
        """Test basic auth header with empty credentials."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            header = config.get_basic_auth_header()
            assert header is None

    def test_effective_auth_type_oauth(self):
        """Test effective auth type with oauth."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_auth_type="oauth", _env_file=None)
            assert config.effective_auth_type == "oauth"

    def test_effective_auth_type_basic(self):
        """Test effective auth type with basic."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_auth_type="basic", _env_file=None)
            assert config.effective_auth_type == "basic"

    def test_effective_auth_type_token(self):
        """Test effective auth type with token."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_auth_type="token", _env_file=None)
            assert config.effective_auth_type == "token"

    def test_effective_auth_type_none(self):
        """Test effective auth type with none."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(server_auth_type="none", _env_file=None)
            assert config.effective_auth_type == "none"

    def test_effective_auth_type_disabled_overrides(self):
        """Test that disable_authorization overrides auth_type."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                server_auth_type="basic",
                server_disable_authorization=True,
                _env_file=None
            )
            assert config.effective_auth_type == "none"

    def test_basic_auth_with_special_characters(self):
        """Test basic auth header with special characters in credentials."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                server_username="user@example.com",
                server_password="p@ss:w0rd!",
                _env_file=None
            )
            header = config.get_basic_auth_header()
            assert header is not None
            # Verify it's valid base64
            import base64
            decoded = base64.b64decode(header).decode('utf-8')
            assert decoded == "user@example.com:p@ss:w0rd!"


class TestReadOnlyMode:
    """Test the read-only mode configuration."""

    def test_read_only_default_false(self):
        """Test that read-only mode is disabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.server_read_only is False

    def test_read_only_enabled(self):
        """Test enabling read-only mode."""
        with patch.dict(os.environ, {"FHIR_SERVER_READ_ONLY": "True"}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.server_read_only is True

    def test_read_only_disabled_explicitly(self):
        """Test explicitly disabling read-only mode."""
        with patch.dict(os.environ, {"FHIR_SERVER_READ_ONLY": "False"}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.server_read_only is False

    def test_read_only_with_various_values(self):
        """Test read-only mode with various boolean string values."""
        # Test truthy values
        for value in ["true", "TRUE", "1", "yes", "YES"]:
            with patch.dict(os.environ, {"FHIR_SERVER_READ_ONLY": value}, clear=True):
                config = ServerConfigs(_env_file=None)
                assert config.server_read_only is True, f"Failed for value: {value}"

        # Test falsy values
        for value in ["false", "FALSE", "0", "no", "NO"]:
            with patch.dict(os.environ, {"FHIR_SERVER_READ_ONLY": value}, clear=True):
                config = ServerConfigs(_env_file=None)
                assert config.server_read_only is False, f"Failed for value: {value}"
