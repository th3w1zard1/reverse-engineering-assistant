/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

import ghidra.base.project.GhidraProject;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.store.LockException;
import ghidra.util.Msg;

/**
 * Utility class for unified project handling across ReVa components.
 * <p>
 * Provides consistent project opening/creation logic for both headless launcher
 * and tool providers, ensuring no conflicts or divergent behavior.
 */
public class ProjectUtil {

    /**
     * Result of a project open operation
     */
    public static class ProjectOpenResult {
        private final Project project;
        private final GhidraProject ghidraProject;
        private final boolean wasAlreadyOpen;
        private final boolean wasCreated;

        private ProjectOpenResult(Project project, GhidraProject ghidraProject, boolean wasAlreadyOpen, boolean wasCreated) {
            this.project = project;
            this.ghidraProject = ghidraProject;
            this.wasAlreadyOpen = wasAlreadyOpen;
            this.wasCreated = wasCreated;
        }

        /**
         * Get the Project instance (may be from active project if locked)
         * @return The Project instance, or null if operation failed
         */
        public Project getProject() {
            return project;
        }

        /**
         * Get the GhidraProject instance (null if project was already open)
         * @return The GhidraProject instance, or null if project was already open
         */
        public GhidraProject getGhidraProject() {
            return ghidraProject;
        }

        /**
         * Check if project was already open (locked, but active project matched)
         * @return True if project was already open
         */
        public boolean wasAlreadyOpen() {
            return wasAlreadyOpen;
        }

        /**
         * Check if project was newly created
         * @return True if project was created, false if it existed
         */
        public boolean wasCreated() {
            return wasCreated;
        }
    }

    /**
     * Create or open a Ghidra project with unified handling.
     * <p>
     * This method provides consistent behavior for:
     * - Creating new projects
     * - Opening existing projects
     * - Handling locked projects (using active project if it matches)
     * - Providing clear error messages
     *
     * @param projectDir The directory where the project is stored
     * @param projectName The name of the project
     * @param enableUpgrade Whether to enable automatic project upgrades (default: true)
     * @param logContext Object for logging context (can be null)
     * @return ProjectOpenResult containing the project and status information
     * @throws IOException if project creation/opening fails and cannot be recovered
     */
    public static ProjectOpenResult createOrOpenProject(
            File projectDir,
            String projectName,
            boolean enableUpgrade,
            Object logContext) throws IOException {
        return createOrOpenProject(projectDir, projectName, enableUpgrade, logContext, false);
    }

    /**
     * Create or open a Ghidra project with unified handling.
     * <p>
     * This method provides consistent behavior for:
     * - Creating new projects
     * - Opening existing projects
     * - Handling locked projects (using active project if it matches)
     * - Force ignoring lock files if requested
     * - Providing clear error messages
     *
     * @param projectDir The directory where the project is stored
     * @param projectName The name of the project
     * @param enableUpgrade Whether to enable automatic project upgrades (default: true)
     * @param logContext Object for logging context (can be null)
     * @param forceIgnoreLock Whether to forcibly delete lock files before opening (default: false)
     * @return ProjectOpenResult containing the project and status information
     * @throws IOException if project creation/opening fails and cannot be recovered
     */
    public static ProjectOpenResult createOrOpenProject(
            File projectDir,
            String projectName,
            boolean enableUpgrade,
            Object logContext,
            boolean forceIgnoreLock) throws IOException {

        // Ensure project directory exists
        if (!projectDir.exists()) {
            if (!projectDir.mkdirs()) {
                throw new IOException("Failed to create project directory: " + projectDir.getAbsolutePath());
            }
        }

        String projectLocationPath = projectDir.getAbsolutePath();
        ProjectLocator locator = new ProjectLocator(projectLocationPath, projectName);

        // If forceIgnoreLock is true, delete lock files before attempting to open
        if (forceIgnoreLock) {
            deleteLockFiles(projectDir, projectName, logContext);
        }

        // Check if project already exists
        boolean projectExists = locator.getMarkerFile().exists() && locator.getProjectDir().exists();

        if (projectExists) {
            // Try to open existing project
            logInfo(logContext, "Opening existing project: " + projectName + " at " + projectLocationPath);
            try {
                GhidraProject ghidraProject = GhidraProject.openProject(projectLocationPath, projectName, enableUpgrade);
                Project project = ghidraProject.getProject();
                return new ProjectOpenResult(project, ghidraProject, false, false);
            } catch (LockException e) {
                // Project is locked - check if it's already open as the active project
                return handleLockedProject(projectLocationPath, projectName, logContext, e);
            } catch (Exception e) {
                // Check if this is an authentication error
                String errorMsg = e.getMessage();
                if (errorMsg != null && (errorMsg.contains("authentication")
                        || errorMsg.contains("password")
                        || errorMsg.contains("login")
                        || errorMsg.contains("unauthorized")
                        || errorMsg.contains("Access denied")
                        || errorMsg.contains("Invalid credentials"))) {
                    throw new IOException(
                        "Authentication failed for shared project. " +
                        "Error: " + errorMsg + ". " +
                        "Please verify your username and password are correct.",
                        e
                    );
                }
                // Re-throw as IOException
                throw new IOException("Failed to open project: " + projectName, e);
            }
        } else {
            // Create new project
            logInfo(logContext, "Creating new project: " + projectName + " at " + projectLocationPath);
            try {
                GhidraProject ghidraProject = GhidraProject.createProject(projectLocationPath, projectName, false);
                Project project = ghidraProject.getProject();
                return new ProjectOpenResult(project, ghidraProject, false, true);
            } catch (Exception e) {
                throw new IOException("Failed to create project: " + projectName, e);
            }
        }
    }

    /**
     * Handle a locked project by checking if the active project matches.
     *
     * @param requestedProjectDir The directory of the requested project
     * @param requestedProjectName The name of the requested project
     * @param logContext Object for logging context (can be null)
     * @param lockException The LockException that was thrown
     * @return ProjectOpenResult with active project if it matches, or throws IOException
     * @throws IOException if active project doesn't match or no active project exists
     */
    private static ProjectOpenResult handleLockedProject(
            String requestedProjectDir,
            String requestedProjectName,
            Object logContext,
            LockException lockException) throws IOException {

        Project activeProject = AppInfo.getActiveProject();
        if (activeProject != null) {
            // Verify the active project matches the requested one
            String activeProjectDir = activeProject.getProjectLocator().getProjectDir().getAbsolutePath();
            String requestedDirAbsolute = new File(requestedProjectDir).getAbsolutePath();

            if (activeProjectDir.equals(requestedDirAbsolute) || activeProject.getName().equals(requestedProjectName)) {
                // Active project matches - use it
                String logMsg = "Project is locked (already open), using active project: " + activeProject.getName();
                logInfo(logContext, logMsg);
                // Return null for ghidraProject since we're using the active project
                return new ProjectOpenResult(activeProject, null, true, false);
            } else {
                // Active project doesn't match
                throw new IOException(
                    "Project '" + requestedProjectName + "' is locked by another process. " +
                    "Active project is '" + activeProject.getName() + "' at '" + activeProjectDir + "'. " +
                    "Please close the project in Ghidra GUI or close the other process using it.",
                    lockException
                );
            }
        } else {
            // No active project available
            throw new IOException(
                "Project '" + requestedProjectName + "' is locked and cannot be opened. " +
                "It may be open in another Ghidra instance. " +
                "Please close the project in Ghidra GUI or close the other process using it.",
                lockException
            );
        }
    }

    /**
     * Verify that a project exists at the given location.
     *
     * @param projectDir The directory where the project should be stored
     * @param projectName The name of the project
     * @return True if the project exists (marker file and project directory both exist)
     */
    public static boolean projectExists(File projectDir, String projectName) {
        ProjectLocator locator = new ProjectLocator(projectDir.getAbsolutePath(), projectName);
        return locator.getMarkerFile().exists() && locator.getProjectDir().exists();
    }

    /**
     * Get the active project if it matches the requested project.
     *
     * @param requestedProjectDir The directory of the requested project
     * @param requestedProjectName The name of the requested project
     * @return The active Project if it matches, or null if it doesn't match or no active project exists
     */
    public static Project getMatchingActiveProject(String requestedProjectDir, String requestedProjectName) {
        Project activeProject = AppInfo.getActiveProject();
        if (activeProject != null) {
            String activeProjectDir = activeProject.getProjectLocator().getProjectDir().getAbsolutePath();
            String requestedDirAbsolute = new File(requestedProjectDir).getAbsolutePath();

            if (activeProjectDir.equals(requestedDirAbsolute) || activeProject.getName().equals(requestedProjectName)) {
                return activeProject;
            }
        }
        return null;
    }

    /**
     * Delete lock files for a project, using rename trick if file handle is in use.
     * <p>
     * Deletes both &lt;projectName&gt;.lock and &lt;projectName&gt;.lock~ files.
     * If direct deletion fails (file handle in use), attempts to rename the file
     * first, then delete it.
     *
     * @param projectDir The directory where the project is stored
     * @param projectName The name of the project
     * @param logContext Object for logging context (can be null)
     */
    public static void deleteLockFiles(File projectDir, String projectName, Object logContext) {
        File lockFile = new File(projectDir, projectName + ".lock");
        File lockFileBackup = new File(projectDir, projectName + ".lock~");

        // Delete main lock file
        if (lockFile.exists()) {
            try {
                if (!lockFile.delete()) {
                    // Try rename trick if direct delete fails (file handle in use)
                    File tempFile = new File(projectDir, projectName + ".lock.tmp." + System.currentTimeMillis());
                    try {
                        Files.move(lockFile.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        tempFile.delete();
                        logInfo(logContext, "Deleted lock file using rename trick: " + lockFile.getName());
                    } catch (IOException e) {
                        logInfo(logContext, "Warning: Could not delete lock file (may be in use): " + lockFile.getName() + " - " + e.getMessage());
                    }
                } else {
                    logInfo(logContext, "Deleted lock file: " + lockFile.getName());
                }
            } catch (Exception e) {
                logInfo(logContext, "Warning: Error deleting lock file: " + lockFile.getName() + " - " + e.getMessage());
            }
        }

        // Delete backup lock file
        if (lockFileBackup.exists()) {
            try {
                if (!lockFileBackup.delete()) {
                    // Try rename trick if direct delete fails
                    File tempFile = new File(projectDir, projectName + ".lock~.tmp." + System.currentTimeMillis());
                    try {
                        Files.move(lockFileBackup.toPath(), tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        tempFile.delete();
                        logInfo(logContext, "Deleted backup lock file using rename trick: " + lockFileBackup.getName());
                    } catch (IOException e) {
                        logInfo(logContext, "Warning: Could not delete backup lock file (may be in use): " + lockFileBackup.getName() + " - " + e.getMessage());
                    }
                } else {
                    logInfo(logContext, "Deleted backup lock file: " + lockFileBackup.getName());
                }
            } catch (Exception e) {
                logInfo(logContext, "Warning: Error deleting backup lock file: " + lockFileBackup.getName() + " - " + e.getMessage());
            }
        }
    }

    /**
     * Log an info message with context
     */
    private static void logInfo(Object logContext, String message) {
        if (logContext != null) {
            Msg.info(logContext, message);
        } else {
            Msg.info(ProjectUtil.class, message);
        }
    }
}
