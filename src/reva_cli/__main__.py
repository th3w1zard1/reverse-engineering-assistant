#!/usr/bin/env python3
"""
ReVa CLI - Main entry point.

Provides stdio MCP transport for ReVa, enabling integration with Claude CLI.
Usage: claude mcp add ReVa -- mcp-reva [--config PATH] [--verbose]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from .launcher import ReVaLauncher
from .project_manager import ProjectManager
from .stdio_bridge import ReVaStdioBridge

if TYPE_CHECKING:
    from types import FrameType


def _redirect_java_outputs():
    """
    Redirect Java's System.out and System.err to Python streams.

    This ensures that Java/Ghidra log messages go through our Python filters
    and get wrapped in JSON-RPC format, preventing them from corrupting the MCP stdio stream.
    """
    try:
        import jpype
        from jpype import JImplements, JOverride  # type: ignore[reportMissingImports]

        if not jpype.isJVMStarted():
            return

        from java.io import PrintStream  # type: ignore[reportMissingImports]
        from java.lang import System  # type: ignore[reportMissingImports]

        @JImplements("java.io.OutputStream")
        class PythonOutputStream:
            """Java OutputStream that writes to Python's wrapped stderr."""

            def __init__(self, python_stream):
                self.python_stream = python_stream
                self._buffer = bytearray()

            @JOverride
            def write(self, *args):
                """Write bytes to Python stream - handles all OutputStream.write() overloads."""
                if len(args) == 1:
                    arg = args[0]
                    if isinstance(arg, int):
                        # write(int b) - single byte
                        self._buffer.append(arg)
                        if arg == ord("\n") or len(self._buffer) > 4096:
                            self._flush_buffer()
                    else:
                        # write(byte[] b) - entire array
                        data = bytes(arg)
                        self._write_data(data)
                elif len(args) == 3:
                    # write(byte[] b, int off, int len) - portion of array
                    b, off, length = args
                    data = bytes(b[off : off + length])
                    self._write_data(data)

            def _write_data(self, data: bytes):
                """Write data bytes to Python stream."""
                try:
                    text = data.decode("utf-8", errors="replace")
                    self.python_stream.write(text)
                    self.python_stream.flush()
                except Exception:
                    pass  # Ignore encoding errors

            def _flush_buffer(self):
                """Flush buffered bytes."""
                if self._buffer:
                    self._write_data(bytes(self._buffer))
                    self._buffer.clear()

            @JOverride
            def flush(self):
                """Flush the stream."""
                self._flush_buffer()
                self.python_stream.flush()

            @JOverride
            def close(self):
                """Close the stream."""
                self._flush_buffer()

        # Create Java PrintStreams that write to Python's wrapped stderr
        python_out_stream = PythonOutputStream(sys.stderr)
        python_err_stream = PythonOutputStream(sys.stderr)

        java_out = PrintStream(python_out_stream, True, "UTF-8")
        java_err = PrintStream(python_err_stream, True, "UTF-8")

        # Redirect Java's System.out and System.err
        System.setOut(java_out)
        System.setErr(java_err)

    except Exception as e:
        # If redirection fails, log to stderr (which is wrapped) and continue
        # Python-level filters will still work for Python code
        try:
            sys.stderr.write(f"Warning: Failed to redirect Java outputs: {e}\n")
        except Exception:
            pass


class StderrFilter:
    """
    Wraps stderr writes in JSON-RPC notification messages to ensure all output is valid JSON.

    All writes to stderr are wrapped in JSON-RPC notifications with method "_log" so they
    can be safely read by MCP clients without causing JSON parsing errors.
    """

    def __init__(self, real_stderr: TextIO):
        self.real_stderr: TextIO = real_stderr
        self._buffer: str = ""
        self._closed: bool = False

    def write(self, s: str) -> int:
        """Write to stderr, wrapping in JSON-RPC notification if needed."""
        if self._closed or not s:
            return 0

        # Add to buffer
        self._buffer += s

        # Flush when we see a newline (complete log message) or buffer gets too large
        if "\n" in self._buffer or len(self._buffer) > 4096:
            # Extract complete lines
            lines = self._buffer.split("\n")
            # Keep the last incomplete line in buffer
            self._buffer = lines[-1]
            # Process complete lines
            for line in lines[:-1]:
                if line.strip():  # Only wrap non-empty lines
                    self._write_jsonrpc_log(line)
            # If buffer is too large, flush it too
            if len(self._buffer) > 4096:
                if self._buffer.strip():
                    self._write_jsonrpc_log(self._buffer)
                self._buffer = ""

        return len(s)

    def _write_jsonrpc_log(self, message: str):
        """Write a log message wrapped in a JSON-RPC notification."""
        # Escape the message for JSON
        escaped_message: str = json.dumps(message)
        # Create JSON-RPC notification
        # Format: {"jsonrpc":"2.0","method":"_log","params":{"message":"..."}}
        jsonrpc_msg: str = (
            '{"jsonrpc":"2.0","method":"_log","params":{"message":'
            + escaped_message
            + "}}\n"
        )
        self.real_stderr.write(jsonrpc_msg)
        self.real_stderr.flush()

    def flush(self):
        """Flush any remaining buffer."""
        if self._buffer:
            if self._buffer.strip():
                self._write_jsonrpc_log(self._buffer)
            self._buffer = ""
        self.real_stderr.flush()

    def close(self):
        """Close the filter (but not the underlying stream)."""
        if not self._closed:
            self.flush()
            self._closed = True

    def __getattr__(self, name):
        """Delegate other attributes to real stderr."""
        return getattr(self.real_stderr, name)


class StdoutFilter:
    """
    Filters stdout writes to prevent non-JSON output from interfering with MCP stdio protocol.

    Writes that look like JSON-RPC messages (start with '{' and contain "jsonrpc") are passed
    through to the real stdout. All other writes are redirected to stderr (which is wrapped
    to ensure JSON-RPC format) to prevent them from corrupting the MCP JSON-RPC stream.

    This handles the case where PyGhidra/Java code writes log messages to stdout, which would
    otherwise corrupt the JSON-RPC protocol stream used by MCP stdio transport.
    """

    def __init__(self, real_stdout: TextIO):
        self.real_stdout: TextIO = real_stdout
        self._buffer: str = ""
        self._closed: bool = False

    def write(self, s: str) -> int:
        """Write to stdout if JSON-RPC, otherwise redirect to wrapped stderr."""
        if self._closed or not s:
            return 0

        # Add to buffer
        self._buffer += s

        # Check if buffer looks like JSON-RPC
        # JSON-RPC messages start with '{' (after whitespace) and contain "jsonrpc"
        buffer_stripped = self._buffer.lstrip()

        if buffer_stripped.startswith("{") and '"jsonrpc"' in self._buffer:
            # This is JSON-RPC - pass through to real stdout
            written = self.real_stdout.write(s)
            self.real_stdout.flush()
            self._buffer = ""  # Clear buffer
            return written

        # Not JSON-RPC - check if we should flush to stderr
        # Flush when we see a newline (typical for log messages) or buffer gets too large
        # Use sys.stderr (which is wrapped) so the write gets JSON-RPC wrapped
        if "\n" in self._buffer or len(self._buffer) > 4096:
            # This is a log message - redirect to wrapped stderr
            written = sys.stderr.write(self._buffer)
            sys.stderr.flush()
            self._buffer = ""
            return written

        # Keep buffering (waiting for newline or more data to determine if it's JSON)
        return len(s)

    def flush(self):
        """Flush both streams."""
        if self._buffer:
            # Check if remaining buffer is JSON-RPC
            buffer_stripped = self._buffer.lstrip()
            if buffer_stripped.startswith("{") and '"jsonrpc"' in self._buffer:
                self.real_stdout.write(self._buffer)
                self.real_stdout.flush()
            else:
                # Flush to wrapped stderr
                sys.stderr.write(self._buffer)
                sys.stderr.flush()
            self._buffer = ""
        self.real_stdout.flush()
        sys.stderr.flush()

    def close(self):
        """Close the filter (but not the underlying streams)."""
        if not self._closed:
            self.flush()
            self._closed = True

    def __getattr__(self, name):
        """Delegate other attributes to real stdout."""
        return getattr(self.real_stdout, name)


class ReVaCLI:
    """Main CLI application."""

    def __init__(
        self,
        launcher: ReVaLauncher,
        project_manager: ProjectManager,
        server_port: int,
    ):
        """
        Initialize ReVa CLI with pre-initialized components.

        Args:
            launcher: Pre-initialized ReVa server launcher
            project_manager: Pre-initialized project manager
            server_port: Port number where ReVa server is running
        """
        self.launcher: ReVaLauncher = launcher
        self.project_manager: ProjectManager = project_manager
        self.server_port: int = server_port
        self.bridge: ReVaStdioBridge | None = None
        self.cleanup_done: bool = False

    def setup_signal_handlers(self):
        """Setup signal handlers for clean shutdown."""

        def signal_handler(sig: int, frame: FrameType | None):
            if not self.cleanup_done:
                sys.stderr.write(
                    f"\nReceived signal {sig}, shutting down gracefully...\n"
                )
                self.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Handle SIGHUP on Unix systems
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    def cleanup(self):
        """Clean up all resources."""
        if self.cleanup_done:
            return

        self.cleanup_done = True
        sys.stderr.write("Cleaning up resources...\n")

        # Stop bridge
        if self.bridge:
            try:
                self.bridge.stop()
            except Exception as e:
                sys.stderr.write(
                    f"Error stopping bridge: {e.__class__.__name__}: {e}\n"
                )

        # Clean up project
        if self.project_manager:
            try:
                self.project_manager.cleanup()
            except Exception as e:
                sys.stderr.write(
                    f"Error cleaning up project: {e.__class__.__name__}: {e}\n"
                )

        # Stop server
        if self.launcher:
            try:
                self.launcher.stop()
            except Exception as e:
                sys.stderr.write(
                    f"Error stopping launcher: {e.__class__.__name__}: {e}\n"
                )

        sys.stderr.write("Cleanup complete\n")

    async def run(self):
        """Run the async stdio bridge (all initialization already done)."""
        try:
            # Setup signal handlers
            self.setup_signal_handlers()

            # Start stdio bridge
            sys.stderr.write(f"Starting stdio bridge on port {self.server_port}...\n")
            self.bridge = ReVaStdioBridge(self.server_port)

            # Run the bridge (this blocks until stopped)
            await self.bridge.run()

        except KeyboardInterrupt:
            sys.stderr.write("\nInterrupted by user\n")
        except Exception as e:
            sys.stderr.write(f"Fatal error: {e.__class__.__name__}: {e}\n")
            import traceback

            traceback.print_exc(file=sys.stderr)
            sys.exit(1)
        finally:
            self.cleanup()


def main():
    """Main entry point for mcp-reva command."""
    parser = argparse.ArgumentParser(
        description="ReVa MCP server with stdio transport for Claude CLI integration",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to ReVa configuration file",
        required=False,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
        default=False,
        required=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 3.0.0",
    )

    args = parser.parse_args()

    # Validate config file if provided
    if args.config and not args.config.exists():
        sys.stderr.write(f"Error: Configuration file not found: {args.config}\n")
        sys.exit(1)

    # =========================================================================
    # BLOCKING INITIALIZATION (before async event loop)
    # =========================================================================
    # All blocking operations happen here to avoid blocking the event loop
    # This ensures the stdio bridge can start immediately when asyncio.run() is called
    #
    # CRITICAL: PyGhidra and Java code may write log messages to stdout during both
    # initialization and runtime. We install a stdout filter that intercepts all writes:
    # - JSON-RPC messages (for MCP protocol) are passed through to real stdout
    # - All other output (logs, prints, etc.) is redirected to stderr
    # This prevents non-JSON text from corrupting the MCP stdio JSON-RPC stream.

    # Save original stdout/stderr
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    try:
        # Install filters BEFORE PyGhidra initializes
        # - stdout: Only allows JSON-RPC messages through
        # - stderr: Wraps all writes in JSON-RPC notifications
        # This ensures ALL output is valid JSON and won't corrupt the MCP stdio stream
        # IMPORTANT: Install stderr filter first, then stdout filter (which uses sys.stderr)
        stderr_filter = StderrFilter(original_stderr)
        sys.stderr = stderr_filter  # type: ignore[assignment]
        stdout_filter = StdoutFilter(original_stdout)
        sys.stdout = stdout_filter  # type: ignore[assignment]

        # Initialize PyGhidra (blocking, 3-5 seconds)
        # Any stdout writes from PyGhidra will be caught by the filter and sent to stderr
        sys.stderr.write("Initializing PyGhidra...\n")
        import pyghidra

        pyghidra.start(verbose=args.verbose)

        # CRITICAL: Redirect Java's System.out/System.err AFTER PyGhidra starts
        # This ensures Java/Ghidra log messages go through our Python filters
        _redirect_java_outputs()

        sys.stderr.write("PyGhidra initialized\n")

        # Initialize project manager (lazy - project created on first tool use)
        sys.stderr.write("Initializing project manager...\n")
        project_manager = ProjectManager()
        sys.stderr.write(
            "Project manager ready (project will be created on first use)\n"
        )

        # Start ReVa server (blocking, 4-7 seconds)
        sys.stderr.write("Starting ReVa server...\n")
        launcher = ReVaLauncher(config_file=args.config, use_random_port=True)
        port = launcher.start()
        sys.stderr.write(f"ReVa server ready on port {port}\n")

        # NOTE: stdout filter remains in place - do NOT restore original_stdout
        # The filter will allow JSON-RPC messages through while redirecting everything else

    except Exception as e:
        # Restore stdout/stderr even on error
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        sys.stderr.write(f"Initialization error: {e.__class__.__name__}: {e}\n")
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    # =========================================================================
    # ASYNC EXECUTION (stdio bridge only)
    # =========================================================================
    # Create CLI with pre-initialized components
    cli = ReVaCLI(launcher=launcher, project_manager=project_manager, server_port=port)

    # Run async event loop (stdio bridge starts immediately)
    try:
        asyncio.run(cli.run())
    except KeyboardInterrupt:
        sys.stderr.write("\nShutdown complete\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
