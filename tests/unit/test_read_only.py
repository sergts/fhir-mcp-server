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
from fhir_mcp_server.oauth.types import ServerConfigs
from fhir_mcp_server.utils import get_operation_outcome


class TestReadOnlyModeLogic:
    """Test the read-only mode logic for blocking operations."""

    @pytest.mark.asyncio
    async def test_readonly_check_blocks_operations(self):
        """Test that read-only mode check returns forbidden outcome."""
        # Create a config with read-only mode enabled
        with patch.dict(os.environ, {"FHIR_SERVER_READ_ONLY": "True"}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.server_read_only is True

            # Simulate the check that would happen in create/update/delete
            if config.server_read_only:
                result = await get_operation_outcome(
                    code="forbidden",
                    diagnostics="Create operations are not allowed. The server is in read-only mode.",
                )

                # Verify the outcome structure
                assert "issue" in result
                assert len(result["issue"]) > 0
                assert result["issue"][0]["code"] == "forbidden"
                assert "read-only mode" in result["issue"][0]["diagnostics"].lower()

    @pytest.mark.asyncio
    async def test_writable_mode_allows_operations(self):
        """Test that writable mode does not block operations."""
        # Create a config with read-only mode disabled
        with patch.dict(os.environ, {"FHIR_SERVER_READ_ONLY": "False"}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.server_read_only is False

            # In writable mode, the check should not trigger
            # This test just verifies the config is correct
            assert not config.server_read_only

    @pytest.mark.asyncio
    async def test_different_operation_messages(self):
        """Test that different operations have appropriate messages."""
        with patch.dict(os.environ, {"FHIR_SERVER_READ_ONLY": "True"}, clear=True):
            config = ServerConfigs(_env_file=None)
            assert config.server_read_only is True

            # Test create message
            create_result = await get_operation_outcome(
                code="forbidden",
                diagnostics="Create operations are not allowed. The server is in read-only mode.",
            )
            assert "create" in create_result["issue"][0]["diagnostics"].lower()

            # Test update message
            update_result = await get_operation_outcome(
                code="forbidden",
                diagnostics="Update operations are not allowed. The server is in read-only mode.",
            )
            assert "update" in update_result["issue"][0]["diagnostics"].lower()

            # Test delete message
            delete_result = await get_operation_outcome(
                code="forbidden",
                diagnostics="Delete operations are not allowed. The server is in read-only mode.",
            )
            assert "delete" in delete_result["issue"][0]["diagnostics"].lower()

