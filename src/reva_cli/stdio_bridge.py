"""
Stdio to HTTP MCP bridge using official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to ReVa's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.

The bridge acts as a transparent proxy - all tool calls, resources, and prompts are
forwarded to the Java ReVa backend running on localhost.
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
from mcp.shared.exceptions import McpError
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
        self._connection_context = None  # Store the connection context for reconnection
        self._connection_params = {
            "timeout": 3600.0,  # 1 hour
            "read_timeout": 1800.0,  # 30 minutes
        }

        # Register handlers
        self._register_handlers()

    async def _ensure_backend_connected(self) -> ClientSession:
        """
        Ensure backend session is connected.

        Returns:
            ClientSession: Active backend session

        Raises:
            RuntimeError: If backend session is not available
        """
        if self.backend_session is None:
            raise RuntimeError("Backend session not initialized - connection lost")
        return self.backend_session

    async def _call_with_reconnect(self, operation_name: str, operation, *args, **kwargs):
        """
        Call a backend operation with automatic retry on "Session terminated" errors.

        Note: Full reconnection requires the outer run() loop to handle it, but we
        can retry the operation in case it was a transient error.

        Args:
            operation_name: Name of the operation for logging
            operation: Async callable to execute
            *args, **kwargs: Arguments to pass to operation

        Returns:
            Result of the operation
        """
        max_retries = 2
        for attempt in range(max_retries):
            try:
                return await operation(*args, **kwargs)
            except McpError as e:
                # Check if this is a "Session terminated" error
                error_str = str(e).lower()
                if "session terminated" in error_str:
                    if attempt < max_retries - 1:
                        sys.stderr.write(
                            f"WARNING: {operation_name} failed with 'Session terminated', "
                            f"retrying (attempt {attempt + 1}/{max_retries})...\n"
                        )
                        # Wait a bit before retrying - sometimes the connection recovers
                        await asyncio.sleep(0.5)
                        # Check if session is still available
                        if self.backend_session is None:
                            raise RuntimeError(
                                "Backend session terminated and cannot be recovered. "
                                "The connection will be re-established on the next request."
                            )
                        # Retry the operation
                        continue
                    else:
                        # After max retries, mark session as dead and raise
                        sys.stderr.write(
                            f"ERROR: {operation_name} failed after {max_retries} attempts: {e}\n"
                        )
                        self.backend_session = None
                        raise RuntimeError(
                            f"Backend session terminated: {e}. "
                            "The connection will be re-established automatically."
                        )
                else:
                    # Not a session termination error, re-raise
                    raise
            except Exception as e:
                # Check if it's a connection-related error
                error_str = str(e).lower()
                error_type = e.__class__.__name__
                if "session" in error_str or "connection" in error_str or "ConnectionError" in error_type:
                    if attempt < max_retries - 1:
                        sys.stderr.write(
                            f"WARNING: {operation_name} failed with connection error, "
                            f"retrying (attempt {attempt + 1}/{max_retries})...\n"
                        )
                        await asyncio.sleep(0.5)
                        if self.backend_session is None:
                            raise RuntimeError(
                                "Backend connection lost and cannot be recovered. "
                                "The connection will be re-established on the next request."
                            )
                        continue
                # For other exceptions, re-raise immediately
                raise

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to ReVa backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Forward list_tools request to ReVa backend with automatic reconnection."""
            await self._ensure_backend_connected()

            async def _list_tools_operation():
                return await asyncio.wait_for(
                    self.backend_session.list_tools(),  # type: ignore
                    timeout=60.0,  # 1 minute for listing tools
                )

            try:
                result = await self._call_with_reconnect("list_tools", _list_tools_operation)
                if result is None:
                    return []
                return result.tools
            except asyncio.TimeoutError:
                sys.stderr.write("ERROR: list_tools timed out\n")
                return []
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: list_tools failed: {e.__class__.__name__}: {e}\n"
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
            """Forward call_tool request to ReVa backend with automatic reconnection."""
            await self._ensure_backend_connected()

            async def _call_tool_operation():
                # Add timeout for tool calls (some Ghidra operations can take a long time)
                return await asyncio.wait_for(
                    self.backend_session.call_tool(name, arguments),  # type: ignore
                    timeout=300.0,  # 5 minutes for tool execution
                )

            try:
                result = await self._call_with_reconnect(
                    f"call_tool({name})", _call_tool_operation
                )
                if result is None:
                    return [TextContent(type="text", text=f"Error: Tool '{name}' returned no result")]
                return result.content
            except asyncio.TimeoutError:
                error_msg = f"Tool '{name}' timed out after 5 minutes"
                sys.stderr.write(f"ERROR: {error_msg}\n")
                return [TextContent(type="text", text=f"Error: {error_msg}")]
            except Exception as e:
                error_msg = f"Tool '{name}' failed: {e.__class__.__name__}: {e}"
                sys.stderr.write(f"ERROR: {error_msg}\n")
                import traceback

                traceback.print_exc(file=sys.stderr)
                return [TextContent(type="text", text=f"Error: {error_msg}")]

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """Forward list_resources request to ReVa backend with automatic reconnection."""
            await self._ensure_backend_connected()

            async def _list_resources_operation():
                return await asyncio.wait_for(
                    self.backend_session.list_resources(),  # type: ignore
                    timeout=60.0,  # 1 minute for listing resources
                )

            try:
                result = await self._call_with_reconnect("list_resources", _list_resources_operation)
                if result is None:
                    return []
                return result.resources
            except asyncio.TimeoutError:
                sys.stderr.write("ERROR: list_resources timed out\n")
                return []
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: list_resources failed: {e.__class__.__name__}: {e}\n"
                )
                return []

        @self.server.read_resource()
        async def read_resource(
            uri: AnyUrl,
        ) -> str | bytes | Iterable[ReadResourceContents]:
            """Forward read_resource request to ReVa backend with automatic reconnection."""
            await self._ensure_backend_connected()

            async def _read_resource_operation():
                return await asyncio.wait_for(
                    self.backend_session.read_resource(uri),  # type: ignore
                    timeout=120.0,  # 2 minutes for reading resources
                )

            try:
                result = await self._call_with_reconnect("read_resource", _read_resource_operation)
                if result is None:
                    return ""
                # Return the first content item's text or blob
                if result.contents and len(result.contents) > 0:
                    content = result.contents[0]
                    if hasattr(content, "text") and content.text:  # pyright: ignore[reportAttributeAccessIssue]
                        return content.text  # pyright: ignore[reportAttributeAccessIssue]
                    elif hasattr(content, "blob") and content.blob:  # pyright: ignore[reportAttributeAccessIssue]
                        return content.blob  # pyright: ignore[reportAttributeAccessIssue]
                return ""
            except asyncio.TimeoutError:
                sys.stderr.write(f"ERROR: read_resource timed out for URI: {uri}\n")
                return ""
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: read_resource failed for URI {uri}: {e.__class__.__name__}: {e}\n"
                )
                return ""

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:
            """Forward list_prompts request to ReVa backend with automatic reconnection."""
            await self._ensure_backend_connected()

            async def _list_prompts_operation():
                return await asyncio.wait_for(
                    self.backend_session.list_prompts(),  # type: ignore
                    timeout=60.0,  # 1 minute for listing prompts
                )

            try:
                result = await self._call_with_reconnect("list_prompts", _list_prompts_operation)
                if result is None:
                    return []
                return result.prompts
            except asyncio.TimeoutError:
                sys.stderr.write("ERROR: list_prompts timed out\n")
                return []
            except Exception as e:
                sys.stderr.write(
                    f"ERROR: list_prompts failed: {e.__class__.__name__}: {e}\n"
                )
                return []

    async def run(self):
        """
        Run the stdio bridge.

        Connects to ReVa backend via StreamableHTTP, initializes the session,
        then exposes the MCP server via stdio transport.
        """
        sys.stderr.write(f"Connecting to ReVa backend at {self.url}...\n")

        # Increased timeout for long-running operations (Ghidra operations can take time)
        # Also increased read timeout to handle slow responses
        # Use very long timeouts to prevent session termination
        timeout = 3600.0  # 1 hour for overall timeout (prevents premature disconnection)
        read_timeout = 1800.0  # 30 minutes for read operations (handles long Ghidra operations)

        max_retries = 3
        retry_delay = 2.0

        for attempt in range(max_retries):
            try:
                # Connect to ReVa backend with increased timeout
                # Note: streamablehttp_client doesn't expose read_timeout directly,
                # but we can configure httpx client with custom timeout
                # The timeout parameter controls both connect and read timeouts
                # Using a very long timeout prevents "Session terminated" errors
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
                            sys.stderr.write("Initializing ReVa backend session...\n")
                            try:
                                init_result = await asyncio.wait_for(
                                    session.initialize(), timeout=read_timeout
                                )
                                sys.stderr.write(
                                    f"Connected to {init_result.serverInfo.name} v{init_result.serverInfo.version}\n"
                                )
                            except asyncio.TimeoutError:
                                sys.stderr.write(
                                    f"Timeout initializing backend session (>{read_timeout}s)\n"
                                )
                                if attempt < max_retries - 1:
                                    sys.stderr.write(
                                        f"Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries})\n"
                                    )
                                    await asyncio.sleep(retry_delay)
                                    continue
                                raise

                            # Run MCP server with stdio transport
                            sys.stderr.write("Bridge ready - stdio transport active\n")
                            try:
                                async with stdio_server() as (stdio_read, stdio_write):
                                    await self.server.run(
                                        stdio_read,
                                        stdio_write,
                                        self.server.create_initialization_options(),
                                    )
                                # If we get here, the server ran successfully
                                break
                            except Exception as stdio_error:
                                # If stdio server fails, check if backend connection is still alive
                                # and attempt to reconnect if needed
                                sys.stderr.write(
                                    f"Stdio server error: {type(stdio_error).__name__}: {stdio_error}\n"
                                )
                                # Check if this is a connection error that warrants retry
                                if isinstance(stdio_error, (ConnectionError, OSError)):
                                    if attempt < max_retries - 1:
                                        sys.stderr.write(
                                            f"Connection error in stdio bridge, retrying... (attempt {attempt + 1}/{max_retries})\n"
                                        )
                                        await asyncio.sleep(retry_delay)
                                        continue
                                # For other errors, re-raise to be handled by outer exception handler
                                raise

            except asyncio.TimeoutError as e:
                sys.stderr.write(
                    f"Timeout error (attempt {attempt + 1}/{max_retries}): {e}\n"
                )
                if attempt < max_retries - 1:
                    sys.stderr.write(f"Retrying in {retry_delay} seconds...\n")
                    await asyncio.sleep(retry_delay)
                    continue
                raise
            except (ConnectionError, OSError) as e:
                sys.stderr.write(
                    f"Connection error (attempt {attempt + 1}/{max_retries}): {e}\n"
                )
                if attempt < max_retries - 1:
                    sys.stderr.write(f"Retrying in {retry_delay} seconds...\n")
                    await asyncio.sleep(retry_delay)
                    continue
                raise
            except Exception as e:
                # For other exceptions, log and re-raise immediately
                sys.stderr.write(f"Bridge error: {e.__class__.__name__}: {e}\n")
                import traceback

                traceback.print_exc(file=sys.stderr)
                raise
            finally:
                self.backend_session = None
                if attempt == max_retries - 1:
                    sys.stderr.write("Bridge stopped\n")

    def stop(self):
        """Stop the bridge (handled by context managers)."""
        # Cleanup is handled by async context managers
        pass
