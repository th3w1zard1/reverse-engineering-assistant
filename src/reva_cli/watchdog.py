"""
Watchdog process for automatic project cleanup.

This module provides a daemon process that monitors the parent MCP server process
and automatically closes/unlocks the Ghidra project when the parent dies or is killed.

The watchdog is completely independent of the parent process and uses multiple
monitoring strategies to ensure reliable cleanup.
"""

from __future__ import annotations

import atexit
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.base.project import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
        GhidraProject,
    )


class ProjectWatchdog:
    """
    Watchdog process that monitors the parent and cleans up the project on shutdown.
    
    Uses multiple monitoring strategies:
    1. Parent PID monitoring (polling)
    2. Signal handlers (SIGTERM, SIGINT)
    3. At-exit handlers
    4. Heartbeat file monitoring (optional)
    """

    def __init__(
        self,
        parent_pid: int,
        project_path: str | Path,
        project_name: str,
        heartbeat_file: Path | None = None,
    ):
        """
        Initialize the watchdog.

        Args:
            parent_pid: PID of the parent process to monitor
            project_path: Path to the Ghidra project directory
            project_name: Name of the Ghidra project
            heartbeat_file: Optional heartbeat file path (parent updates this)
        """
        self.parent_pid = parent_pid
        self.project_path = Path(project_path)
        self.project_name = project_name
        self.heartbeat_file = heartbeat_file
        self.ghidra_project: GhidraProject | None = None
        self.cleanup_done = False
        self.poll_interval = 1.0  # Check parent every second
        self.heartbeat_timeout = 10.0  # Consider parent dead if no heartbeat for 10 seconds

    def _is_parent_alive(self) -> bool:
        """
        Check if the parent process is still alive.

        Returns:
            True if parent is alive, False otherwise
        """
        try:
            # On Unix, kill(pid, 0) checks if process exists without sending a signal
            # On Windows, we need to use a different approach
            if sys.platform == "win32":
                # Windows: Try to open the process
                import ctypes

                kernel32 = ctypes.windll.kernel32
                PROCESS_QUERY_INFORMATION = 0x0400
                handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, self.parent_pid)
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:
                # Unix: Use kill(pid, 0) to check existence
                os.kill(self.parent_pid, 0)
                return True
        except (OSError, ProcessLookupError):
            # Process doesn't exist
            return False
        except Exception:
            # Other error - assume parent is alive to be safe
            return True

    def _check_heartbeat(self) -> bool:
        """
        Check if parent is still sending heartbeats.

        Returns:
            True if heartbeat is recent, False if stale or missing
        """
        if not self.heartbeat_file or not self.heartbeat_file.exists():
            return True  # No heartbeat file means we're not using heartbeat monitoring

        try:
            # Read heartbeat timestamp
            with open(self.heartbeat_file, "r") as f:
                data = json.load(f)
                last_heartbeat = data.get("timestamp", 0)
                current_time = time.time()
                return (current_time - last_heartbeat) < self.heartbeat_timeout
        except Exception:
            # If we can't read heartbeat, assume it's stale
            return False

    def _cleanup_project(self):
        """Close and unlock the Ghidra project."""
        if self.cleanup_done:
            return

        self.cleanup_done = True

        try:
            # Import Ghidra modules
            from ghidra.base.project import (  # type: ignore[reportMissingImports, reportMissingModuleSource]
                GhidraProject,
            )
            from ghidra.framework.model import (  # type: ignore[reportMissingImports, reportMissingModuleSource]
                ProjectLocator,
            )
            from ghidra.framework.main import AppInfo  # type: ignore[reportMissingImports, reportMissingModuleSource]

            sys.stderr.write(
                f"[Watchdog] Attempting to close project: {self.project_name}\n"
            )

            # First, try to close the active project if it matches
            try:
                active_project = AppInfo.getActiveProject()
                if active_project:
                    active_locator = active_project.getProjectLocator()
                    if (
                        active_locator.getProjectDir().getAbsolutePath()
                        == str(self.project_path.resolve())
                        and active_project.getName() == self.project_name
                    ):
                        sys.stderr.write(
                            f"[Watchdog] Closing active project: {self.project_name}\n"
                        )
                        active_project.close()
                        sys.stderr.write(
                            "[Watchdog] Successfully closed active project\n"
                        )
                        return
            except Exception as e:
                sys.stderr.write(
                    f"[Watchdog] Error closing active project: {e}\n"
                )

            # Try to get the project if we have a reference
            if self.ghidra_project:
                try:
                    if not self.ghidra_project.getProject().isClosed():
                        sys.stderr.write(
                            f"[Watchdog] Closing project reference: {self.project_name}\n"
                        )
                        self.ghidra_project.close()
                        sys.stderr.write(
                            "[Watchdog] Successfully closed project reference\n"
                        )
                        return
                except Exception as e:
                    sys.stderr.write(
                        f"[Watchdog] Error closing project reference: {e}\n"
                    )
                finally:
                    self.ghidra_project = None

            # Try to open and close the project directly
            # This ensures the lock is released even if the reference is invalid
            try:
                project_locator = ProjectLocator(
                    str(self.project_path), self.project_name
                )
                if project_locator.exists():
                    # Try to open the project with upgrade disabled
                    # If it's locked, this will fail, but we'll try anyway
                    try:
                        sys.stderr.write(
                            "[Watchdog] Attempting to open project for cleanup...\n"
                        )
                        temp_project = GhidraProject.openProject(
                            str(self.project_path), self.project_name, False
                        )
                        # If we can open it, close it to release the lock
                        sys.stderr.write(
                            "[Watchdog] Opened project, closing to release lock...\n"
                        )
                        temp_project.close()
                        sys.stderr.write(
                            f"[Watchdog] Project unlocked successfully: {self.project_name}\n"
                        )
                    except Exception as e:
                        # Project might be locked by another process or already closed
                        error_msg = str(e).lower()
                        if "lock" in error_msg or "locked" in error_msg:
                            sys.stderr.write(
                                "[Watchdog] Project is locked (may be in use by another process)\n"
                            )
                        else:
                            sys.stderr.write(
                                f"[Watchdog] Could not open project for cleanup: {e}\n"
                            )
            except Exception as e:
                sys.stderr.write(
                    f"[Watchdog] Error during project cleanup: {e}\n"
                )

        except ImportError:
            # Ghidra not available - can't clean up
            sys.stderr.write(
                "[Watchdog] Warning: Ghidra not available, cannot clean up project\n"
            )
        except Exception as e:
            sys.stderr.write(f"[Watchdog] Unexpected error during cleanup: {e}\n")

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""

        def signal_handler(sig, frame):
            sys.stderr.write(f"[Watchdog] Received signal {sig}, cleaning up...\n")
            self._cleanup_project()
            sys.exit(0)

        # Register signal handlers
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

        # Register at-exit handler
        atexit.register(self._cleanup_project)

    def run(self):
        """
        Run the watchdog loop.

        Monitors the parent process and cleans up the project when it dies.
        """
        self._setup_signal_handlers()

        sys.stderr.write(
            f"[Watchdog] Started monitoring parent PID {self.parent_pid}\n"
        )
        sys.stderr.write(
            f"[Watchdog] Project: {self.project_name} at {self.project_path}\n"
        )

        try:
            while True:
                # Check if parent is still alive
                if not self._is_parent_alive():
                    sys.stderr.write(
                        f"[Watchdog] Parent process {self.parent_pid} is dead, cleaning up...\n"
                    )
                    self._cleanup_project()
                    break

                # Check heartbeat if enabled
                if self.heartbeat_file and not self._check_heartbeat():
                    sys.stderr.write(
                        "[Watchdog] Heartbeat timeout, parent may be dead, cleaning up...\n"
                    )
                    self._cleanup_project()
                    break

                # Sleep before next check
                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            sys.stderr.write("[Watchdog] Interrupted, cleaning up...\n")
            self._cleanup_project()
        except Exception as e:
            sys.stderr.write(f"[Watchdog] Error in monitoring loop: {e}\n")
            self._cleanup_project()
        finally:
            sys.stderr.write("[Watchdog] Exiting\n")


def spawn_watchdog(
    parent_pid: int,
    project_path: str | Path,
    project_name: str,
    heartbeat_file: Path | None = None,
) -> int | None:
    """
    Spawn a detached watchdog process.

    The watchdog process is completely independent of the parent and will
    continue running even if the parent is killed.

    Args:
        parent_pid: PID of the parent process to monitor
        project_path: Path to the Ghidra project directory
        project_name: Name of the Ghidra project
        heartbeat_file: Optional heartbeat file path

    Returns:
        PID of the spawned watchdog process
    """
    import subprocess

    # Get the path to this script
    script_path: Path = Path(__file__).resolve()
    python_exe: str = sys.executable

    # Prepare arguments
    args: list[str] = [
        python_exe,
        str(script_path),
        "--parent-pid",
        str(parent_pid),
        "--project-path",
        str(project_path),
        "--project-name",
        project_name,
    ]

    if heartbeat_file:
        args.extend(["--heartbeat-file", str(heartbeat_file)])

    # Spawn detached process
    # On Unix: Use double-fork to detach from parent
    # On Windows: Use CREATE_NO_WINDOW to prevent console window from appearing
    if sys.platform == "win32":
        # Windows: Use CREATE_NO_WINDOW to prevent any console window from appearing
        # This prevents the console from being created at all, which is more reliable
        # than DETACHED_PROCESS which can still cause a brief flash
        # Also use STARTUPINFO with SW_HIDE as a backup to ensure window stays hidden
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        # CREATE_NO_WINDOW prevents console creation entirely (most reliable)
        # Don't use DETACHED_PROCESS as it can still cause window flash
        creation_flags = subprocess.CREATE_NO_WINDOW
        
        process = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,  # Keep stderr for debugging
            stdin=subprocess.DEVNULL,
            creationflags=creation_flags,
            startupinfo=startupinfo,
            start_new_session=True,
        )
        return process.pid
    else:
        # Unix: Double-fork to detach
        # First fork
        pid: int = os.fork()
        if pid == 0:
            # Child process - second fork
            pid2: int = os.fork()
            if pid2 == 0:
                # Grandchild - this is the detached process
                # Redirect stdio
                sys.stdin.close()
                sys.stdout.close()
                # Keep stderr open for logging
                # Start new session
                os.setsid()
                # Run the watchdog
                watchdog = ProjectWatchdog(
                    parent_pid, project_path, project_name, heartbeat_file
                )
                watchdog.run()
            else:
                # First child exits immediately
                os._exit(0)
        else:
            # Parent waits for first child to exit
            os.waitpid(pid, 0)
            # Return a dummy PID (the actual watchdog PID is in the grandchild)
            # We can't easily get it, but that's OK - the process is detached
            return 0


def main():
    """Main entry point for watchdog process."""
    import argparse

    parser = argparse.ArgumentParser(description="ReVa project cleanup watchdog")
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--project-path", type=str, required=True)
    parser.add_argument("--project-name", type=str, required=True)
    parser.add_argument("--heartbeat-file", type=str, required=False)

    args = parser.parse_args()

    heartbeat_file = Path(args.heartbeat_file) if args.heartbeat_file else None

    # Initialize PyGhidra if not already initialized
    # The watchdog runs in a separate process, so PyGhidra needs to be initialized here
    try:
        import pyghidra

        if not pyghidra.started():
            sys.stderr.write("[Watchdog] Initializing PyGhidra...\n")
            pyghidra.start(verbose=False)
            sys.stderr.write("[Watchdog] PyGhidra initialized\n")
        else:
            sys.stderr.write("[Watchdog] PyGhidra already initialized\n")
    except Exception as e:
        sys.stderr.write(f"[Watchdog] Warning: Failed to initialize PyGhidra: {e}\n")
        sys.stderr.write(
            "[Watchdog] Will attempt cleanup when parent dies, but may not succeed\n"
        )
        # Continue anyway - cleanup might still work if PyGhidra is available

    # Create and run watchdog
    watchdog = ProjectWatchdog(
        args.parent_pid,
        args.project_path,
        args.project_name,
        heartbeat_file,
    )
    watchdog.run()


if __name__ == "__main__":
    main()
