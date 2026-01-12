"""
Stdio to HTTP MCP bridge using official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to ReVa's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING, Any, Iterable

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp.types import (
    JSONRPCMessage,
    JSONRPCNotification,
    TextContent,
)

if TYPE_CHECKING:
    from mcp.server.lowlevel.helper_types import ReadResourceContents
    from mcp.server.lowlevel.server import (
        CombinationContent,
        StructuredContent,
        UnstructuredContent,
    )
    from mcp.types import (
        CallToolResult,
        Prompt,
        Resource,
        Tool,
    )
    from pydantic import AnyUrl


class JsonEnvelopeStream:
    """
    Wraps the MCP stream to handle parsing errors gracefully.
    The stream yields SessionMessage objects or Exception objects.
    When the MCP SDK fails to parse a log message as JSON-RPC, it creates an Exception.
    We catch those exceptions and convert them to valid SessionMessage objects.
    """

    def __init__(self, original_stream):
        self.original_stream = original_stream

    async def __aenter__(self):
        # If original stream supports context manager, enter it
        if hasattr(self.original_stream, "__aenter__"):
            return await self.original_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # If original stream supports context manager, exit it
        if hasattr(self.original_stream, "__aexit__"):
            return await self.original_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            item = await self.original_stream.__anext__()
        except StopAsyncIteration:
            raise

        # The stream yields SessionMessage | Exception
        # If it's an Exception (parsing error from log message), convert it to a valid SessionMessage
        if isinstance(item, Exception):
            # Extract the log message from the exception
            error_msg = str(item)
            # Create a valid JSON-RPC notification message for the log
            # Use a notification (no id) so it doesn't break request/response flow
            notification = JSONRPCNotification(
                jsonrpc="2.0",
                method="_log",
                params={"message": error_msg},
            )
            return SessionMessage(JSONRPCMessage(notification))

        # If it's already a SessionMessage, pass it through unchanged
        return item


class ReVaStdioBridge:
    """
    MCP Server that bridges stdio to ReVa's StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the ReVa backend
    and returns responses. The MCP SDK handles all JSON-RPC serialization.
    """

    def __init__(self, port: int):
        """
        Initialize the stdio bridge.

        Args:
            port: ReVa server port to connect to
        """
        self.port = port
        self.url = f"http://localhost:{port}/mcp/message"
        self.server = Server("ReVa")
        self.backend_session: ClientSession | None = None

        # Register handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to ReVa backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Forward list_tools request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            try:
                result = await asyncio.wait_for(
                    self.backend_session.list_tools(),
                    timeout=60.0,  # 1 minute for listing tools
                )
                return result.tools
            except asyncio.TimeoutError:
                print("ERROR: list_tools timed out", file=sys.stderr)
                return []
            except Exception as e:
                print(
                    f"ERROR: list_tools failed: {type(e).__name__}: {str(e)}",
                    file=sys.stderr,
                )
                return []

        @self.server.call_tool()
        async def call_tool(
            name: str,
            arguments: dict[str, Any],
        ) -> (
            UnstructuredContent
            | StructuredContent
            | CombinationContent
            | CallToolResult
        ):
            """Forward call_tool request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            try:
                # Add timeout for tool calls (some Ghidra operations can take a long time)
                result = await asyncio.wait_for(
                    self.backend_session.call_tool(name, arguments),
                    timeout=300.0,  # 5 minutes for tool execution
                )
                return result.content
            except asyncio.TimeoutError:
                error_msg = f"Tool '{name}' timed out after 5 minutes"
                print(f"ERROR: {error_msg}", file=sys.stderr)
                return [TextContent(type="text", text=f"Error: {error_msg}")]
            except Exception as e:
                error_msg = f"Tool '{name}' failed: {type(e).__name__}: {str(e)}"
                print(f"ERROR: {error_msg}", file=sys.stderr)
                import traceback

                traceback.print_exc(file=sys.stderr)
                return [TextContent(type="text", text=f"Error: {error_msg}")]

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """Forward list_resources request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            try:
                result = await asyncio.wait_for(
                    self.backend_session.list_resources(),
                    timeout=60.0,  # 1 minute for listing resources
                )
                return result.resources
            except asyncio.TimeoutError:
                print("ERROR: list_resources timed out", file=sys.stderr)
                return []
            except Exception as e:
                print(
                    f"ERROR: list_resources failed: {type(e).__name__}: {str(e)}",
                    file=sys.stderr,
                )
                return []

        @self.server.read_resource()
        async def read_resource(
            uri: AnyUrl,
        ) -> str | bytes | Iterable[ReadResourceContents]:
            """Forward read_resource request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            try:
                result = await asyncio.wait_for(
                    self.backend_session.read_resource(uri),
                    timeout=120.0,  # 2 minutes for reading resources
                )
                # Return the first content item's text or blob
                if result.contents and len(result.contents) > 0:
                    content = result.contents[0]
                    if hasattr(content, "text") and content.text:  # pyright: ignore[reportAttributeAccessIssue]
                        return content.text  # pyright: ignore[reportAttributeAccessIssue]
                    elif hasattr(content, "blob") and content.blob:  # pyright: ignore[reportAttributeAccessIssue]
                        return content.blob  # pyright: ignore[reportAttributeAccessIssue]
                return ""
            except asyncio.TimeoutError:
                print(f"ERROR: read_resource timed out for URI: {uri}", file=sys.stderr)
                return ""
            except Exception as e:
                print(
                    f"ERROR: read_resource failed for URI {uri}: {type(e).__name__}: {str(e)}",
                    file=sys.stderr,
                )
                return ""

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:
            """Forward list_prompts request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            try:
                result = await asyncio.wait_for(
                    self.backend_session.list_prompts(),
                    timeout=60.0,  # 1 minute for listing prompts
                )
                return result.prompts
            except asyncio.TimeoutError:
                print("ERROR: list_prompts timed out", file=sys.stderr)
                return []
            except Exception as e:
                print(
                    f"ERROR: list_prompts failed: {type(e).__name__}: {str(e)}",
                    file=sys.stderr,
                )
                return []

    async def run(self):
        """
        Run the stdio bridge.

        Connects to ReVa backend via StreamableHTTP, initializes the session,
        then exposes the MCP server via stdio transport.
        """
        print(f"Connecting to ReVa backend at {self.url}...", file=sys.stderr)

        # Increased timeout for long-running operations (Ghidra operations can take time)
        # Also increased read timeout to handle slow responses
        timeout = 600.0  # 10 minutes for overall timeout
        read_timeout = 300.0  # 5 minutes for read operations

        max_retries = 3
        retry_delay = 2.0

        for attempt in range(max_retries):
            try:
                # Connect to ReVa backend with increased timeout
                # Note: streamablehttp_client doesn't expose read_timeout directly,
                # but we can configure httpx client with custom timeout
                async with streamablehttp_client(self.url, timeout=timeout) as (
                    read_stream,
                    write_stream,
                    get_session_id,
                ):
                    # Wrap read_stream to convert non-JSON messages to valid JSON
                    # This prevents JSON parsing errors while preserving all log messages
                    json_stream = JsonEnvelopeStream(read_stream)

                    # Enter the wrapper's context manager
                    async with json_stream:
                        async with ClientSession(json_stream, write_stream) as session:  # pyright: ignore[reportArgumentType]
                            self.backend_session = session

                            # Initialize backend session with timeout
                            print(
                                "Initializing ReVa backend session...", file=sys.stderr
                            )
                            try:
                                init_result = await asyncio.wait_for(
                                    session.initialize(), timeout=read_timeout
                                )
                                print(
                                    f"Connected to {init_result.serverInfo.name} v{init_result.serverInfo.version}",
                                    file=sys.stderr,
                                )
                            except asyncio.TimeoutError:
                                print(
                                    f"Timeout initializing backend session (>{read_timeout}s)",
                                    file=sys.stderr,
                                )
                                if attempt < max_retries - 1:
                                    print(
                                        f"Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries})",
                                        file=sys.stderr,
                                    )
                                    await asyncio.sleep(retry_delay)
                                    continue
                                raise

                            # Run MCP server with stdio transport
                            print(
                                "Bridge ready - stdio transport active", file=sys.stderr
                            )
                            async with stdio_server() as (stdio_read, stdio_write):
                                await self.server.run(
                                    stdio_read,
                                    stdio_write,
                                    self.server.create_initialization_options(),
                                )
                            # If we get here, the server ran successfully
                            break

            except asyncio.TimeoutError as e:
                print(
                    f"Timeout error (attempt {attempt + 1}/{max_retries}): {e}",
                    file=sys.stderr,
                )
                if attempt < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds...", file=sys.stderr)
                    await asyncio.sleep(retry_delay)
                    continue
                raise
            except (ConnectionError, OSError) as e:
                print(
                    f"Connection error (attempt {attempt + 1}/{max_retries}): {e}",
                    file=sys.stderr,
                )
                if attempt < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds...", file=sys.stderr)
                    await asyncio.sleep(retry_delay)
                    continue
                raise
            except Exception as e:
                # For other exceptions, log and re-raise immediately
                print(f"Bridge error: {type(e).__name__}: {e}", file=sys.stderr)
                import traceback

                traceback.print_exc(file=sys.stderr)
                raise
            finally:
                self.backend_session = None
                if attempt == max_retries - 1:
                    print("Bridge stopped", file=sys.stderr)

    def stop(self):
        """Stop the bridge (handled by context managers)."""
        # Cleanup is handled by async context managers
        pass
