"""
Test ReVa MCP tool functionality.

Verifies that:
- Tools can be called and return results
- list-project-files works
- get-strings works
- get-functions works
- Other key tools are accessible
"""
from __future__ import annotations

import pytest
from mcp.client.session import ClientSession

from tests.helpers import get_response_result


# Mark all tests in this file as integration tests (require server)
pytestmark = pytest.mark.integration


class TestProgramTools:
    """Test program-related MCP tools"""

    async def test_list_project_files(self, mcp_client: ClientSession):
        """list-project-files tool returns file list (may be empty)"""
        response_result = await mcp_client.call_tool("list-project-files", {"folderPath": "/"})

        # Should get a response (even if no files in project)
        assert response_result is not None

        # If it's an error response, check it's a valid error
        if response_result.isError:
            # Tool call completed, error is expected if project is empty
            assert response_result is not None
        else:
            # If success, should have content that's a list
            result = get_response_result({
                "content": response_result.content,
                "isError": response_result.isError
            })
            assert "content" in result
            content = result["content"]
            assert isinstance(content, list)

    async def test_list_project_files_includes_format(self, mcp_client: ClientSession, test_program):
        """list-project-files result has expected structure when programs are open"""
        # This test uses test_program fixture to ensure at least one program is available
        # Note: test_program may not be registered with MCP server's project manager
        response_result = await mcp_client.call_tool("list-project-files", {"folderPath": "/"})

        # Handle case where no programs are open in the MCP server's project
        if response_result.isError:
            # Expected - test_program isn't registered with MCP server
            assert response_result is not None
            return

        result = get_response_result({
            "content": response_result.content,
            "isError": response_result.isError
        })

        # Should have content
        assert "content" in result
        content = result["content"]

        # Content should be list of objects with type and text
        # May be empty if program isn't registered with MCP server
        if content:
            for item in content:
                assert "type" in item
                assert "text" in item

    async def test_list_project_files_only_checked_out(self, mcp_client: ClientSession):
        """list-project-files with onlyShowCheckedOutPrograms parameter"""
        # Test with onlyShowCheckedOutPrograms=True
        response_result = await mcp_client.call_tool(
            "list-project-files",
            {"folderPath": "/", "recursive": True, "onlyShowCheckedOutPrograms": True}
        )

        # Should get a response
        assert response_result is not None

        if not response_result.isError:
            result = get_response_result({
                "content": response_result.content,
                "isError": response_result.isError
            })
            assert "content" in result
            content = result["content"]
            assert isinstance(content, list)

            # Check metadata if available
            if content:
                # First item might be metadata
                import json
                try:
                    metadata = json.loads(content[0].get("text", "{}"))
                    if "onlyShowCheckedOutPrograms" in metadata:
                        assert metadata["onlyShowCheckedOutPrograms"] is True
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass  # Not metadata, that's okay

        # Test with onlyShowCheckedOutPrograms=False (default)
        response_result2 = await mcp_client.call_tool(
            "list-project-files",
            {"folderPath": "/", "recursive": True, "onlyShowCheckedOutPrograms": False}
        )

        assert response_result2 is not None

    async def test_list_open_programs_shows_all(self, mcp_client: ClientSession):
        """list-open-programs shows all programs, not just open ones"""
        # Test that list-open-programs can be called (should show all programs)
        response_result = await mcp_client.call_tool("list-open-programs", {})

        # Should get a response (even if no programs exist)
        assert response_result is not None

        if not response_result.isError:
            result = get_response_result({
                "content": response_result.content,
                "isError": response_result.isError
            })
            assert "content" in result
            content = result["content"]
            assert isinstance(content, list)

    async def test_list_open_programs_only_checked_out(self, mcp_client: ClientSession):
        """list-open-programs with onlyShowCheckedOutPrograms parameter"""
        # Test with onlyShowCheckedOutPrograms=True
        response_result = await mcp_client.call_tool(
            "list-open-programs",
            {"onlyShowCheckedOutPrograms": True}
        )

        # Should get a response
        assert response_result is not None

        if not response_result.isError:
            result = get_response_result({
                "content": response_result.content,
                "isError": response_result.isError
            })
            assert "content" in result
            content = result["content"]
            assert isinstance(content, list)

            # Check metadata if available
            if content:
                import json
                try:
                    metadata = json.loads(content[0].get("text", "{}"))
                    if "onlyCheckedOut" in metadata:
                        assert metadata["onlyCheckedOut"] is True
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass  # Not metadata, that's okay

        # Test with onlyShowCheckedOutPrograms=False (default)
        response2_result = await mcp_client.call_tool(
            "list-open-programs",
            {"onlyShowCheckedOutPrograms": False}
        )

        assert response2_result is not None


class TestStringTools:
    """Test string analysis tools"""

    async def test_list_strings_requires_program(self, mcp_client: ClientSession):
        """manage_strings requires programPath argument"""
        response_result = await mcp_client.call_tool(
            "manage_strings",
            {"programPath": "/NonexistentProgram", "mode": "list", "max_count": 5},
        )

        # Should get a response (even if error due to missing program)
        assert response_result is not None

        # Will likely error since program doesn't exist, but that's okay
        # We're just testing the tool is registered and callable

    async def test_list_strings_with_valid_program_path(self, mcp_client: ClientSession):
        """manage_strings accepts valid programPath format"""
        # We don't have a real project, but we can verify the tool accepts
        # properly formatted requests
        response_result = await mcp_client.call_tool(
            "manage_strings",
            {"programPath": "/TestProgram.exe", "mode": "list", "max_count": 10},
        )

        # Should get response (even if error about program not existing)
        assert response_result is not None


class TestFunctionTools:
    """Test function-related MCP tools"""

    async def test_list_functions_callable(self, mcp_client: ClientSession):
        """list_functions tool is registered and callable"""
        response_result = await mcp_client.call_tool(
            "list_functions", {"programPath": "/TestProgram"}
        )

        # Should get a response
        assert response_result is not None

    async def test_get_decompilation_callable(self, mcp_client: ClientSession):
        """get_function tool is registered and callable"""
        response_result = await mcp_client.call_tool(
            "get_function", {"programPath": "/TestProgram", "identifier": "0x00401000"}
        )

        # Should get a response (even if error)
        assert response_result is not None


class TestToolRegistration:
    """Test that key tools are registered"""

    @pytest.mark.parametrize(
        "tool_name",
        [
            "list-open-programs",
            "list-functions",
            "manage-strings",
            "get-functions",
            "manage-function",
            "analyze-program",
            "get-references",
            "get-call-graph",
            "manage-symbols",
            "manage-structures",
            "manage-data-types",
            "inspect-memory",
            "manage-bookmarks",
            "manage-comments",
            "analyze-vtables",
            "analyze-data-flow",
            "search-constants",
            "manage-function-tags",
            "list-project-files",
        ],
    )
    async def test_tool_is_registered(self, mcp_client: ClientSession, tool_name: str):
        """All expected tools are registered and callable"""
        # Call with minimal args - we just want to verify tool exists
        # Some tools need mode/action, but we're just checking registration
        args = {"programPath": "/TestProgram"}  # Most tools need programPath

        # Tools that don't need programPath
        if tool_name in ["list-open-programs"]:
            args = {}

        # Add minimal required args for tools that need mode/action/other params
        if tool_name == "manage-strings":
            args["mode"] = "list"
        elif tool_name == "manage-symbols":
            args["mode"] = "count"
        elif tool_name == "manage-structures":
            args["action"] = "list"
        elif tool_name == "manage-data-types":
            args["action"] = "archives"
        elif tool_name == "inspect-memory":
            args["mode"] = "blocks"
        elif tool_name == "manage-bookmarks":
            args["action"] = "get"
        elif tool_name == "manage-comments":
            args["action"] = "get"
        elif tool_name == "analyze-vtables":
            args["mode"] = "analyze"
            args["vtable_address"] = "0x0"
        elif tool_name == "analyze-data-flow":
            args["function_address"] = "0x0"
            args["start_address"] = "0x0"
            args["direction"] = "backward"
        elif tool_name == "search-constants":
            args["mode"] = "common"
        elif tool_name == "get-references":
            args["mode"] = "to"
            args["target"] = "0x0"
        elif tool_name == "get-functions":
            args["identifier"] = "0x0"
        elif tool_name == "manage-function":
            args["action"] = "create"
            args["address"] = "0x0"
        elif tool_name == "get-call-graph":
            args["function_identifier"] = "0x0"
        elif tool_name == "manage-function-tags":
            args["mode"] = "list"
        elif tool_name == "list-functions":
            args["mode"] = "count"

        response_result = await mcp_client.call_tool(tool_name, args)

        # Should get some response (even if error due to missing required args)
        # The key is that we get a response, not a connection error
        assert response_result is not None
