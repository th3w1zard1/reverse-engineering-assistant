"""
Project management for ReVa CLI.

Handles creation and management of Ghidra projects in .reva/projects/
within the current working directory, similar to how .git or .vscode work.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.base.project import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        GhidraProject,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        Program,
    )


def _spawn_project_watchdog(
    project_path: Path,
    project_name: str,
) -> int | None:
    """Spawn a detached watchdog process to monitor this process and clean up the project.

    Args:
        project_path: Path to the Ghidra project directory
        project_name: Name of the Ghidra project

    Returns:
        Watchdog PID if spawned successfully, None otherwise
    """
    try:
        from .watchdog import spawn_watchdog

        parent_pid = os.getpid()
        watchdog_pid = spawn_watchdog(parent_pid, project_path, project_name)
        if watchdog_pid:
            sys.stderr.write(
                f"Spawned project watchdog (PID: {watchdog_pid}) to monitor cleanup\n"
            )
        return watchdog_pid
    except Exception as e:
        # Don't fail if watchdog can't be spawned - just log and continue
        sys.stderr.write(
            f"Warning: Failed to spawn project watchdog: {e.__class__.__name__}: {e}\n"
        )
        return None


class ProjectManager:
    """Manages Ghidra project creation and lifecycle for ReVa CLI."""

    def __init__(
        self,
        projects_dir: Path | None = None,
    ):
        """Initialize project manager.

        Args:
            projects_dir: Custom projects directory, defaults to .reva/projects/ in current directory
        """
        if projects_dir is None:
            self.projects_dir = Path.cwd() / ".reva" / "projects"
        else:
            self.projects_dir = Path(projects_dir)

        # Don't create directory here - defer until first tool use (lazy initialization)
        self.project: GhidraProject | None = None
        self._opened_programs: list[Program] = []
        self._initialized: bool = False
        self._watchdog_pid: int | None = None

    def _ensure_initialized(self):
        """Ensure the project directory exists and project is opened.

        This implements lazy initialization - the .reva directory and Ghidra project
        are only created when first needed (e.g., when importing a binary).
        """
        if self._initialized:
            return

        # Create projects directory
        self.projects_dir.mkdir(parents=True, exist_ok=True)

        # Open/create the Ghidra project
        self.open_project()

        # Spawn watchdog process to ensure project cleanup on shutdown
        project_name, project_path = self.get_or_create_project()
        self._watchdog_pid = _spawn_project_watchdog(project_path, project_name)

        self._initialized = True

    def get_project_name(self) -> str:
        """Get project name based on current working directory.

        Returns:
            Project name derived from current directory name
        """
        cwd = Path.cwd()
        # Use current directory name as project name
        project_name = cwd.name.strip()

        # Sanitize project name for Ghidra
        # Remove invalid characters and replace with underscores
        sanitized = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in project_name
        )

        # Ensure name is not empty
        if not sanitized or sanitized.startswith("."):
            sanitized = "default_project"

        return sanitized

    def get_or_create_project(self) -> tuple[str, Path]:
        """Get or create Ghidra project for current working directory.

        Returns:
            Tuple of (project_name, project_directory_path)
        """
        project_name = self.get_project_name()
        project_path = self.projects_dir / project_name

        # Create project directory if it doesn't exist
        project_path.mkdir(parents=True, exist_ok=True)

        return project_name, project_path

    def open_project(self) -> GhidraProject:
        """Open or create Ghidra project using PyGhidra.

        Returns:
            Ghidra Project instance (GhidraProject wrapper)

        Raises:
            ImportError: If Ghidra/PyGhidra not available
        """
        try:
            from ghidra.base.project import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                GhidraProject,
            )
            from ghidra.framework.model import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                ProjectLocator,
            )
        except ImportError as e:
            raise ImportError(
                "Ghidra modules not available. Ensure PyGhidra is installed and Ghidra is initialized."
            ) from e

        project_name, project_path = self.get_or_create_project()

        # Check if we should force ignore lock files
        force_ignore_lock: bool = os.getenv(
            "REVA_FORCE_IGNORE_LOCK", ""
        ).lower().strip() in (
            "true",
            "1",
            "yes",
            "y",
        )
        if force_ignore_lock:
            self._delete_lock_files(project_path, project_name)

        # Use GhidraProject (PyGhidra's approach) - handles protected constructor properly
        project_locator = ProjectLocator(str(project_path), project_name)

        # Try to open existing project or create new one
        if (
            project_locator.getProjectDir().exists()
            and project_locator.getMarkerFile().exists()
        ):
            sys.stderr.write(f"Opening existing project: {project_name}\n")
            self.project = GhidraProject.openProject(
                str(project_path), project_name, True
            )
        else:
            sys.stderr.write(
                f"Creating new project: {project_name} at {project_path}\n"
            )
            project_path.mkdir(parents=True, exist_ok=True)
            self.project = GhidraProject.createProject(
                str(project_path), project_name, False
            )

        return self.project

    def _delete_lock_files(
        self,
        project_path: Path,
        project_name: str,
    ) -> None:
        """Delete lock files for a project, using rename trick if file handle is in use.

        Deletes both <projectName>.lock and <projectName>.lock~ files.
        If direct deletion fails (file handle in use), attempts to rename the file
        first, then delete it.

        Args:
            project_path: Path to the Ghidra project directory
            project_name: Name of the Ghidra project
        """
        import time

        lock_file: Path = project_path / f"{project_name}.lock"
        lock_file_backup: Path = project_path / f"{project_name}.lock~"

        # Delete main lock file
        if lock_file.exists() and lock_file.is_file():
            try:
                lock_file.unlink(missing_ok=True)
                sys.stderr.write(f"Deleted lock file: {lock_file.name}\n")
            except (OSError, PermissionError):
                # Try rename trick if direct delete fails (file handle in use)
                try:
                    temp_file = (
                        project_path
                        / f"{project_name}.lock.tmp.{int(time.time() * 1000)}"
                    )
                    os.rename(str(lock_file), str(temp_file))
                    temp_file.unlink()
                    sys.stderr.write(
                        f"Deleted lock file using rename trick: {lock_file.name}\n"
                    )
                except Exception as rename_error:
                    sys.stderr.write(
                        f"Warning: Could not delete lock file (may be in use): {lock_file.name} - {rename_error}\n"
                    )

        # Delete backup lock file
        if lock_file_backup.exists() and lock_file_backup.is_file():
            try:
                lock_file_backup.unlink(missing_ok=True)
                sys.stderr.write(f"Deleted backup lock file: {lock_file_backup.name}\n")
            except (OSError, PermissionError):
                # Try rename trick if direct delete fails
                try:
                    temp_file = (
                        project_path
                        / f"{project_name}.lock~.tmp.{int(time.time() * 1000)}"
                    )
                    os.rename(str(lock_file_backup), str(temp_file))
                    temp_file.unlink(missing_ok=True)
                    sys.stderr.write(
                        f"Deleted backup lock file using rename trick: {lock_file_backup.name}\n"
                    )
                except Exception as rename_error:
                    sys.stderr.write(
                        f"Warning: Could not delete backup lock file (may be in use): {lock_file_backup.name} - {rename_error}\n"
                    )

    def import_binary(
        self,
        binary_path: Path,
        program_name: str | None = None,
    ) -> Program | None:
        """Import a binary file into the opened project.

        Args:
        ----
            binary_path: Path to binary file to import
            program_name: Optional custom program name, defaults to binary filename

        Returns:
        -------
            Imported Program instance, or None if import fails
        """
        # Ensure project is initialized (lazy initialization on first use)
        self._ensure_initialized()

        if not binary_path.exists() or not binary_path.is_file():
            sys.stderr.write(f"Warning: Binary not found: {binary_path}\n")
            return None

        if program_name is None or not program_name.strip():
            program_name = binary_path.name

        try:
            sys.stderr.write(f"Importing binary: '{binary_path}' as '{program_name}'\n")

            # Use GhidraProject's importProgram method (auto-detects language/loader)
            program: Program | None = self.project.importProgram(str(binary_path))  # pyright: ignore[reportOptionalMemberAccess, reportArgumentType, reportUnknownLambdaType]

            if program is not None:
                # Save with custom name if specified
                if program_name != binary_path.name:
                    self.project.saveAs(program, "/", program_name, True)  # pyright: ignore[reportOptionalMemberAccess]

                self._opened_programs.append(program)
                sys.stderr.write(f"Successfully imported: '{program_name}'\n")
                return program
            else:
                sys.stderr.write(f"Failed to import: '{binary_path}'\n")
                return None

        except Exception as e:
            sys.stderr.write(
                f"Error importing binary '{binary_path}': {e.__class__.__name__}: {e}\n"
            )
            import traceback

            traceback.print_exc(file=sys.stderr)
            return None

    def cleanup(self):
        """Clean up opened programs and close project."""
        # Release opened programs
        for program in self._opened_programs:
            try:
                if program is not None and not program.isClosed():
                    program.release(None)
            except Exception as e:
                sys.stderr.write(
                    f"Error releasing program: {e.__class__.__name__}: {e}\n"
                )

        self._opened_programs.clear()

        # Close project
        if self.project:
            try:
                self.project.close()
            except Exception as e:
                sys.stderr.write(
                    f"Error closing project: {e.__class__.__name__}: {e}\n"
                )
            finally:
                self.project = None
