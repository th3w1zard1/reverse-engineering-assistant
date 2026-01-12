"""
Java ReVa launcher wrapper for Python CLI.

Handles PyGhidra initialization, ReVa server startup, and project management.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reva.headless import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        RevaHeadlessLauncher,
    )


class ReVaLauncher:
    """Wraps ReVa headless launcher with Python-side project management.

    Note: Stdio mode uses ephemeral projects in temp directories.
    Projects are created per-session and cleaned up on exit.
    """

    def __init__(
        self,
        config_file: Path | None = None,
        use_random_port: bool = True,
    ):
        """
        Initialize ReVa launcher.

        Args:
            config_file: Optional configuration file path
            use_random_port: Whether to use random available port (default: True)
        """
        self.config_file: Path | None = config_file
        self.use_random_port: bool = use_random_port
        self.java_launcher: RevaHeadlessLauncher | None = None
        self.port: int | None = None
        self.temp_project_dir: Path | None = None

    def start(self) -> int:
        """
        Start ReVa headless server.

        Returns:
            Server port number

        Raises:
            RuntimeError: If server fails to start
        """
        try:
            # Import ReVa launcher (PyGhidra already initialized by CLI)
            import tempfile

            from java.io import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                File,
            )
            from reva.headless import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                RevaHeadlessLauncher,
            )

            from .project_manager import ProjectManager

            # Stdio mode: ephemeral projects in temp directory (session-scoped, auto-cleanup)
            # Keeps working directory clean - no .reva creation in cwd
            self.temp_project_dir = Path(tempfile.mkdtemp(prefix="reva_project_"))
            project_manager = ProjectManager()
            project_name = project_manager.get_project_name()

            # Use temp directory for the project (not .reva/projects)
            projects_dir = self.temp_project_dir

            # Convert to Java File objects
            java_project_location = File(str(projects_dir))

            print(f"Project location: {projects_dir}/{project_name}", file=sys.stderr)

            # Create launcher with project parameters
            if self.config_file:
                print(f"Using config file: {self.config_file}", file=sys.stderr)
                java_config_file = File(str(self.config_file))
                self.java_launcher = RevaHeadlessLauncher(
                    java_config_file,
                    self.use_random_port,
                    java_project_location,
                    project_name,
                )
            else:
                print("Using default configuration", file=sys.stderr)
                # Use constructor with project parameters
                self.java_launcher = RevaHeadlessLauncher(
                    None,
                    True,  # autoInitializeGhidra
                    self.use_random_port,
                    java_project_location,
                    project_name,
                )

            # Start server
            print("Starting ReVa MCP server...", file=sys.stderr)
            self.java_launcher.start()  # pyright: ignore[reportOptionalMemberAccess]

            # Wait for server to be ready
            if self.java_launcher.waitForServer(30000):  # pyright: ignore[reportOptionalMemberAccess]
                self.port = self.java_launcher.getPort()  # pyright: ignore[reportOptionalMemberAccess]
                print(f"ReVa server ready on port {self.port}", file=sys.stderr)
                return self.port  # pyright: ignore[reportReturnType]
            else:
                raise RuntimeError("Server failed to start within timeout")

        except Exception as e:
            print(f"Error starting ReVa server: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc(file=sys.stderr)
            raise

    def get_port(self) -> int | None:
        """
        Get the server port.

        Returns:
            Server port number, or None if not started
        """
        return self.port

    def is_running(self) -> bool:
        """
        Check if server is running.

        Returns:
            True if server is running
        """
        if self.java_launcher:
            return self.java_launcher.isRunning()
        return False

    def stop(self):
        """Stop the ReVa server and cleanup."""
        if self.java_launcher:
            print("Stopping ReVa server...", file=sys.stderr)
            try:
                self.java_launcher.stop()
            except Exception as e:
                print(f"Error stopping server: {e}", file=sys.stderr)
            finally:
                self.java_launcher = None
                self.port = None

        # Clean up temporary project directory
        if self.temp_project_dir and self.temp_project_dir.exists():
            try:
                import shutil

                shutil.rmtree(self.temp_project_dir)
                print(
                    f"Cleaned up temporary project directory: {self.temp_project_dir}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"Error cleaning up temporary directory: {e}", file=sys.stderr)
            finally:
                self.temp_project_dir = None
