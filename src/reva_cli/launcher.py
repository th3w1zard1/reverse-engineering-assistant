"""
Java ReVa launcher wrapper for Python CLI.

Handles PyGhidra initialization, ReVa server startup, and project management.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reva.headless import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        RevaHeadlessLauncher,
    )


def _spawn_project_watchdog(
    project_path: Path,
    project_name: str,
) -> int | None:
    """
    Spawn a detached watchdog process to monitor this process and clean up the project.

    Args:
        project_path: Path to the Ghidra project directory
        project_name: Name of the Ghidra project

    Returns:
        Watchdog PID if spawned successfully, None otherwise
    """
    try:
        from .watchdog import spawn_watchdog

        parent_pid: int = os.getpid()
        watchdog_pid: int | None = spawn_watchdog(parent_pid, project_path, project_name)
        if watchdog_pid:
            sys.stderr.write(
                f"Spawned project watchdog (PID: {watchdog_pid}) to monitor cleanup\n"
            )
    except Exception as e:
        # Don't fail if watchdog can't be spawned - just log and continue
        sys.stderr.write(f"Warning: Failed to spawn project watchdog: {e}\n")
        return None
    else:
        return watchdog_pid


class ReVaLauncher:
    """Wraps ReVa headless launcher with Python-side project management.

    Note: Stdio mode uses ephemeral projects in temp directories by default.
    Projects are created per-session and cleaned up on exit.
    If REVA_PROJECT_PATH environment variable is set, uses that project instead.
    """

    def __init__(
        self,
        config_file: Path | None = None,
        use_random_port: bool = True,
    ):
        """
        Initialize ReVa launcher.

        Args:
        ----
            config_file: Optional configuration file path
            use_random_port: Whether to use random available port (default: True)
        """
        self.config_file: Path | None = config_file
        self.use_random_port: bool = use_random_port
        self.java_launcher: RevaHeadlessLauncher | None = None
        self.port: int | None = None
        self.temp_project_dir: Path | None = None
        self.user_project_path: Path | None = None

    def start(self) -> int:
        """
        Start ReVa headless server.

        Returns:
        -------
            Server port number

        Raises:
        ------
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

            # Check for REVA_PROJECT_PATH environment variable
            project_gpr_path = os.getenv("REVA_PROJECT_PATH")

            if project_gpr_path:
                # Use user-specified project from environment variable
                project_gpr = Path(project_gpr_path)

                # Validate it's a .gpr file
                if not project_gpr.suffix.lower() == ".gpr":
                    raise ValueError(
                        f"REVA_PROJECT_PATH must point to a .gpr file, got: {project_gpr_path}"
                    )

                # Validate the file exists
                if not project_gpr.exists():
                    raise FileNotFoundError(
                        f"Project file specified in REVA_PROJECT_PATH does not exist: {project_gpr_path}"
                    )

                # Extract project directory and name (same logic as open tool for projects)
                project_dir = project_gpr.parent
                project_name = project_gpr.stem  # Gets filename without extension

                if not project_name:
                    raise ValueError(
                        f"Invalid project name extracted from path: {project_gpr_path}"
                    )

                # Store the user project path (so we don't clean it up)
                self.user_project_path = project_gpr

                # Use the project directory
                projects_dir = project_dir

                sys.stderr.write(
                    f"Using project from REVA_PROJECT_PATH: {project_gpr}\n"
                )
                sys.stderr.write(f"Project location: {projects_dir}/{project_name}\n")
            else:
                # Stdio mode: ephemeral projects in temp directory (session-scoped, auto-cleanup)
                # Keeps working directory clean - no .reva creation in cwd
                self.temp_project_dir = Path(tempfile.mkdtemp(prefix="reva_project_"))
                project_manager = ProjectManager()
                project_name = project_manager.get_project_name()

                # Use temp directory for the project (not .reva/projects)
                projects_dir = self.temp_project_dir

                sys.stderr.write(f"Project location: {projects_dir}/{project_name}\n")

            # Convert to Java File objects
            java_project_location = File(str(projects_dir))

            # Create launcher with project parameters
            if self.config_file:
                sys.stderr.write(f"Using config file: {self.config_file}\n")
                java_config_file = File(str(self.config_file))
                self.java_launcher = RevaHeadlessLauncher(
                    java_config_file,
                    self.use_random_port,
                    java_project_location,
                    project_name,
                )
            else:
                sys.stderr.write("Using default configuration\n")
                # Use constructor with project parameters
                self.java_launcher = RevaHeadlessLauncher(
                    None,
                    True,  # autoInitializeGhidra
                    self.use_random_port,
                    java_project_location,
                    project_name,
                )

            # Start server
            sys.stderr.write("Starting ReVa MCP server...\n")
            self.java_launcher.start()  # pyright: ignore[reportOptionalMemberAccess]

            # Wait for server to be ready
            if self.java_launcher.waitForServer(30000):  # pyright: ignore[reportOptionalMemberAccess]
                self.port = self.java_launcher.getPort()  # pyright: ignore[reportOptionalMemberAccess]
                sys.stderr.write(f"ReVa server ready on port {self.port}\n")

                # Spawn watchdog process to ensure project cleanup on shutdown
                # Only spawn for user-specified projects (not temp projects)
                if self.user_project_path:
                    _spawn_project_watchdog(projects_dir, project_name)

                return self.port  # pyright: ignore[reportReturnType]
            else:
                raise RuntimeError("Server failed to start within timeout")

        except Exception as e:
            sys.stderr.write(f"Error starting ReVa server: {e}\n")
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
        --------
            True if server is running
        """
        if self.java_launcher:
            return self.java_launcher.isRunning()
        return False

    def stop(self):
        """Stop the ReVa server and cleanup."""
        if self.java_launcher:
            sys.stderr.write("Stopping ReVa server...\n")
            try:
                self.java_launcher.stop()
            except Exception as e:
                sys.stderr.write(f"Error stopping server: {e}\n")
            finally:
                self.java_launcher = None
                self.port = None

        # Clean up temporary project directory (only if using temp project, not user project)
        if self.temp_project_dir and self.temp_project_dir.exists():
            try:
                import shutil

                shutil.rmtree(self.temp_project_dir)
                sys.stderr.write(
                    f"Cleaned up temporary project directory: {self.temp_project_dir}\n"
                )
            except Exception as e:
                sys.stderr.write(f"Error cleaning up temporary directory: {e}\n")
            finally:
                self.temp_project_dir = None
