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
package reva.headless;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.Msg;
import reva.plugin.ConfigManager;
import reva.server.McpServerManager;
import reva.util.ProjectUtil;
import utility.application.ApplicationLayout;

/**
 * Headless launcher for ReVa MCP server.
 * <p>
 * This class enables ReVa to run in headless Ghidra mode without the GUI plugin system.
 * It can be invoked from pyghidra or other headless contexts.
 * <p>
 * Projects are ephemeral in stdio mode - created in temp directories and cleaned up on exit.
 * <p>
 * Usage from pyghidra:
 * <pre>
 * from reva.headless import RevaHeadlessLauncher
 *
 * launcher = RevaHeadlessLauncher()
 * launcher.start()
 *
 * # Server is now running
 * if launcher.waitForServer(30000):
 *     print(f"Server ready on port {launcher.getPort()}")
 *
 * # Do work...
 *
 * launcher.stop()
 * </pre>
 */
public class RevaHeadlessLauncher {

    private static final String LOCK_ENV_VAR = "REVA_FORCE_IGNORE_LOCK";
    private static final List<String> LOCK_FILE_SUFFIXES = List.of(".lock", ".lock~", ".~lock");
    private static final Pattern PID_KEY_PATTERN =
        Pattern.compile("(?i)\\b(pid|process(?:\\s*id)?)\\b\\s*[:=]\\s*(\\d+)");
    private static final Pattern GENERIC_NUMBER_PATTERN = Pattern.compile("\\b(\\d{4,6})\\b");
    private static final long MIN_WINDOWS_PID = 1000;
    private static final long MAX_WINDOWS_PID = 99999;

    private McpServerManager serverManager;
    private ConfigManager configManager;
    private File configFile;
    private boolean autoInitializeGhidra;
    private boolean useRandomPort;
    private File projectLocation;
    private String projectName;
    private GhidraProject ghidraProject;

    /**
     * Constructor with default settings (in-memory configuration)
     */
    public RevaHeadlessLauncher() {
        this(null, true, false);
    }

    /**
     * Constructor with configuration file
     * @param configFile The configuration file to load, or null for defaults
     */
    public RevaHeadlessLauncher(File configFile) {
        this(configFile, true, false);
    }

    /**
     * Constructor with configuration file path
     * Convenience constructor for PyGhidra scripts that use string paths
     * @param configFilePath Path to the configuration file
     */
    public RevaHeadlessLauncher(String configFilePath) {
        this(new File(configFilePath), true, false);
    }

    /**
     * Constructor with random port option
     * @param configFile The configuration file to load, or null for defaults
     * @param useRandomPort Whether to use a random available port instead of configured port
     */
    public RevaHeadlessLauncher(File configFile, boolean useRandomPort) {
        this(configFile, true, useRandomPort);
    }

    /**
     * Constructor with full control
     * @param configFile The configuration file to load, or null for defaults
     * @param autoInitializeGhidra Whether to automatically initialize Ghidra if not already initialized
     * @param useRandomPort Whether to use a random available port instead of configured port
     */
    public RevaHeadlessLauncher(File configFile, boolean autoInitializeGhidra, boolean useRandomPort) {
        this(configFile, autoInitializeGhidra, useRandomPort, null, null);
    }

    /**
     * Constructor with project parameters
     * @param configFile The configuration file to load, or null for defaults
     * @param useRandomPort Whether to use a random available port instead of configured port
     * @param projectLocation The directory where projects are stored (e.g., .reva/projects)
     * @param projectName The name of the project to create/open
     */
    public RevaHeadlessLauncher(File configFile, boolean useRandomPort, File projectLocation, String projectName) {
        this(configFile, true, useRandomPort, projectLocation, projectName);
    }

    /**
     * Constructor with full control and project parameters
     * @param configFile The configuration file to load, or null for defaults
     * @param autoInitializeGhidra Whether to automatically initialize Ghidra if not already initialized
     * @param useRandomPort Whether to use a random available port instead of configured port
     * @param projectLocation The directory where projects are stored (e.g., .reva/projects), or null for no project
     * @param projectName The name of the project to create/open, or null for no project
     */
    public RevaHeadlessLauncher(File configFile, boolean autoInitializeGhidra, boolean useRandomPort,
                               File projectLocation, String projectName) {
        this.configFile = configFile;
        this.autoInitializeGhidra = autoInitializeGhidra;
        this.useRandomPort = useRandomPort;
        this.projectLocation = projectLocation;
        this.projectName = projectName;
    }

    /**
     * Start the MCP server in headless mode
     * @throws IOException if configuration file cannot be read
     * @throws IllegalStateException if Ghidra is not initialized and autoInitializeGhidra is false
     */
    public void start() throws IOException {
        Msg.info(this, "Starting ReVa MCP server in headless mode...");

        // Initialize Ghidra application if needed
        if (!Application.isInitialized()) {
            if (autoInitializeGhidra) {
                Msg.info(this, "Initializing Ghidra application in headless mode...");
                try {
                    ApplicationLayout layout = new GhidraApplicationLayout();
                    ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
                    Application.initializeApplication(layout, config);
                    Msg.info(this, "Ghidra application initialized");
                } catch (IOException e) {
                    throw new IOException("Failed to initialize Ghidra application layout", e);
                }
            } else {
                throw new IllegalStateException(
                    "Ghidra application is not initialized. " +
                    "Call Application.initializeApplication() first or set autoInitializeGhidra=true");
            }
        }

        // Create config manager based on mode
        if (configFile != null) {
            Msg.info(this, "Loading configuration from: " + configFile.getAbsolutePath());
            configManager = new ConfigManager(configFile);
        } else {
            Msg.info(this, "Using default configuration (in-memory)");
            configManager = new ConfigManager();
        }

        // Use random port if requested
        if (useRandomPort) {
            int randomPort = configManager.setRandomAvailablePort();
            Msg.info(this, "Using random port: " + randomPort);
        }

        // Create/open persistent project if location and name specified
        if (projectLocation != null && projectName != null) {
            boolean forceIgnoreLock = isForceIgnoreLockEnabled();
            if (forceIgnoreLock) {
                releaseLockFiles(projectLocation, projectName);
            }

            try {
                ProjectUtil.ProjectOpenResult result = ProjectUtil.createOrOpenProject(
                    projectLocation, projectName, true, this, forceIgnoreLock);
                ghidraProject = result.getGhidraProject();
                if (result.wasAlreadyOpen()) {
                    Msg.info(this, "Project '" + projectName + "' is already open, using active project");
                } else if (result.wasCreated()) {
                    Msg.info(this, "Created new project: " + projectName);
                } else {
                    Msg.info(this, "Opened project: " + projectName);
                }
            } catch (IOException e) {
                if (forceIgnoreLock && isLockRelatedError(e)) {
                    Msg.info(this, "Project is locked, attempting to delete lock files and retry...");
                    releaseLockFiles(projectLocation, projectName);
                    try {
                        ProjectUtil.ProjectOpenResult result = ProjectUtil.createOrOpenProject(
                            projectLocation, projectName, true, this, true);
                        ghidraProject = result.getGhidraProject();
                        if (result.wasAlreadyOpen()) {
                            Msg.info(this, "Project '" + projectName + "' is already open, using active project");
                        } else {
                            Msg.info(this, "Opened project after deleting lock files: " + projectName);
                        }
                    } catch (IOException retryException) {
                        // IMPORTANT: Do not crash the MCP server if a project cannot be opened.
                        // The server should still start so users can choose/open another project.
                        Msg.error(this,
                            "Failed to open project after deleting lock files: " + projectName +
                                ". Starting ReVa without an active project.",
                            retryException);
                        ghidraProject = null;
                    }
                } else {
                    // IMPORTANT: Do not crash the MCP server if a project cannot be opened.
                    // Starting without an active project is valid; tools will surface "no active project"
                    // errors where appropriate and project-management tools can still be used.
                    Msg.error(this,
                        "Failed to open project '" + projectName + "'. Starting ReVa without an active project. " +
                            "You can open a different project using the project tools.",
                        e);
                    ghidraProject = null;
                }
            } catch (Exception e) {
                // IMPORTANT: Do not crash the MCP server if a project cannot be opened.
                Msg.error(this,
                    "Failed to create/open project '" + projectName + "'. Starting ReVa without an active project.",
                    e);
                ghidraProject = null;
            }
        }

        // Create and start server manager
        serverManager = new McpServerManager(configManager);
        serverManager.startServer();

        Msg.info(this, "ReVa MCP server started in headless mode");
    }


    /**
     * Stop the server and cleanup
     */
    public void stop() {
        Msg.info(this, "Stopping ReVa MCP server...");

        if (serverManager != null) {
            serverManager.shutdown();
            serverManager = null;
        }

        if (configManager != null) {
            configManager.dispose();
            configManager = null;
        }

        // Close Ghidra project (but don't delete it - it's persistent)
        if (ghidraProject != null) {
            try {
                Msg.info(this, "Closing project: " + projectName);
                ghidraProject.close();
            } catch (Exception e) {
                Msg.error(this, "Error closing project: " + e.getMessage(), e);
            } finally {
                ghidraProject = null;
            }
        }

        Msg.info(this, "ReVa MCP server stopped");
    }

    /**
     * Get the server port
     * @return The server port, or -1 if server is not running
     */
    public int getPort() {
        if (serverManager != null) {
            return serverManager.getServerPort();
        }
        return -1;
    }

    /**
     * Check if server is running
     * @return True if the server is running
     */
    public boolean isRunning() {
        return serverManager != null && serverManager.isServerRunning();
    }

    /**
     * Check if server is ready to accept connections
     * @return True if the server is ready
     */
    public boolean isServerReady() {
        return serverManager != null && serverManager.isServerReady();
    }

    /**
     * Wait for server to be ready
     * @param timeoutMs Maximum time to wait in milliseconds
     * @return True if server became ready within timeout, false otherwise
     */
    @SuppressWarnings("BusyWait")
    public boolean waitForServer(long timeoutMs) {
        long start = System.currentTimeMillis();
        long elapsed;
        while ((elapsed = System.currentTimeMillis() - start) < timeoutMs) {
            if (isRunning() && isServerReady()) {
                return true;
            }
            long remaining = timeoutMs - elapsed;
            if (remaining <= 0) {
                break;
            }
            if (!sleepWithInterrupt(Math.min(100, remaining))) {
                return false;
            }
        }
        return false;
    }

    /**
     * Sleep for the specified duration, handling interrupts
     * @param ms Duration to sleep in milliseconds
     * @return True if sleep completed normally, false if interrupted
     */
    private boolean sleepWithInterrupt(long ms) {
        try {
            Thread.sleep(ms);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static boolean isForceIgnoreLockEnabled() {
        String forceIgnoreLockEnv = System.getenv(LOCK_ENV_VAR);
        return forceIgnoreLockEnv != null &&
            (forceIgnoreLockEnv.equalsIgnoreCase("true") ||
             forceIgnoreLockEnv.equalsIgnoreCase("1"));
    }

    private static boolean isLockRelatedError(IOException e) {
        String errorMessage = e.getMessage();
        if (errorMessage == null) {
            return false;
        }
        String normalized = errorMessage.toLowerCase(Locale.ENGLISH);
        return normalized.contains("locked") && normalized.contains("cannot be opened");
    }

    private static boolean isWindows() {
        String osName = System.getProperty("os.name", "");
        return osName.toLowerCase(Locale.ENGLISH).contains("win");
    }

    private void releaseLockFiles(File projectLocation, String projectName) {
        if (isWindows()) {
            handleWindowsLockFiles(projectLocation, projectName);
        }
        ProjectUtil.deleteLockFiles(projectLocation, projectName, this);
    }

    private void handleWindowsLockFiles(File projectLocation, String projectName) {
        if (projectLocation == null || !projectLocation.exists()) {
            return;
        }
        Map<Long, Set<File>> lockingProcesses = collectLockOwners(projectLocation, projectName);
        if (lockingProcesses.isEmpty()) {
            return;
        }

        long currentPid = ProcessHandle.current().pid();
        for (Map.Entry<Long, Set<File>> entry : lockingProcesses.entrySet()) {
            long pid = entry.getKey();
            if (pid == currentPid) {
                Msg.info(this, "Current process (" + pid + ") already owns lock files for project " + projectName);
                continue;
            }
            terminateLockingProcess(pid, entry.getValue());
        }
    }

    private Map<Long, Set<File>> collectLockOwners(File projectLocation, String projectName) {
        Map<Long, Set<File>> owners = new LinkedHashMap<>();
        for (String suffix : LOCK_FILE_SUFFIXES) {
            File lockFile = new File(projectLocation, projectName + suffix);
            if (!lockFile.exists() || !lockFile.isFile()) {
                continue;
            }
            Set<Long> pids = parsePidsFromLockFile(lockFile);
            for (Long pid : pids) {
                owners.computeIfAbsent(pid, $ -> new LinkedHashSet<>()).add(lockFile);
            }
        }
        return owners;
    }

    private Set<Long> parsePidsFromLockFile(File lockFile) {
        Set<Long> pids = new LinkedHashSet<>();
        try {
            String content = Files.readString(lockFile.toPath(), StandardCharsets.UTF_8);
            Matcher kvMatcher = PID_KEY_PATTERN.matcher(content);
            while (kvMatcher.find()) {
                addPidCandidate(kvMatcher.group(2), pids);
            }
            if (pids.isEmpty()) {
                Matcher genericMatcher = GENERIC_NUMBER_PATTERN.matcher(content);
                while (genericMatcher.find()) {
                    addPidCandidate(genericMatcher.group(1), pids);
                }
            }
            if (!pids.isEmpty()) {
                Msg.info(this, "Detected potential locking PID(s) " + pids + " in " + lockFile.getName());
            }
        } catch (IOException e) {
            Msg.warn(this, "Unable to read lock file '" + lockFile.getAbsolutePath() + "': " + e.getMessage());
        }
        return pids;
    }

    private void addPidCandidate(String rawPid, Set<Long> pids) {
        if (rawPid == null) {
            return;
        }
        try {
            long pid = Long.parseLong(rawPid);
            if (pid >= MIN_WINDOWS_PID && pid <= MAX_WINDOWS_PID) {
                pids.add(pid);
            }
        } catch (NumberFormatException ignored) {
            // Ignore unparsable values
        }
    }

    private void terminateLockingProcess(long pid, Set<File> lockFiles) {
        String fileDescription = lockFiles.stream()
            .map(File::getName)
            .collect(Collectors.joining(", "));
        Msg.info(this, "Detected Windows lock held by pid " + pid + " for files [" + fileDescription + "]");

        ProcessHandle.of(pid).ifPresentOrElse(handle -> {
            if (!handle.isAlive()) {
                Msg.info(this, "Process " + pid + " already exited.");
                return;
            }
            String commandDescription = handle.info().command().orElse("unknown");
            Msg.info(this, "Requesting graceful termination of process " + pid + " (" + commandDescription + ")");
            try {
                handle.destroy();
            } catch (UnsupportedOperationException | SecurityException ex) {
                Msg.warn(this, "Unable to request graceful termination of process " + pid + ": " + ex.getMessage());
            }

            if (!waitForProcessExit(handle, 2000)) {
                Msg.info(this, "Process " + pid + " still alive after graceful request; forcing termination");
                try {
                    handle.destroyForcibly();
                } catch (UnsupportedOperationException | SecurityException ex) {
                    Msg.warn(this, "Unable to forcefully terminate process " + pid + ": " + ex.getMessage());
                }
                if (!waitForProcessExit(handle, 2000)) {
                    Msg.warn(this, "Process " + pid + " remained alive after forced termination attempt");
                } else {
                    Msg.info(this, "Process " + pid + " terminated after forced termination");
                }
            } else {
                Msg.info(this, "Process " + pid + " terminated gracefully");
            }
        }, () -> Msg.info(this, "No running process found for pid " + pid));
    }

    private boolean waitForProcessExit(ProcessHandle handle, long timeoutMs) {
        long waitInterval = 200;
        long waited = 0;
        while (handle.isAlive() && waited < timeoutMs) {
            try {
                Thread.sleep(waitInterval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            waited += waitInterval;
        }
        return !handle.isAlive();
    }

    /**
     * Get the configuration manager
     * @return The configuration manager, or null if not started
     */
    public ConfigManager getConfigManager() {
        return configManager;
    }

    /**
     * Get the server manager
     * @return The server manager, or null if not started
     */
    public McpServerManager getServerManager() {
        return serverManager;
    }

    /**
     * Main method for standalone execution
     * <p>
     * Example usage:
     * <pre>
     * java -cp ... reva.headless.RevaHeadlessLauncher [configFile]
     * </pre>
     *
     * @param args Optional configuration file path as first argument
     */
    public static void main(String[] args) {
        // Parse arguments
        File configFile = null;
        if (args.length > 0) {
            configFile = new File(args[0]);
            if (!configFile.exists()) {
                System.err.println("Configuration file not found: " + configFile.getAbsolutePath());
                System.exit(1);
            }
        }

        // Create and start launcher
        RevaHeadlessLauncher launcher = new RevaHeadlessLauncher(configFile);

        try {
            launcher.start();

            // Wait for server to be ready
            if (launcher.waitForServer(30000)) {
                System.out.println("ReVa MCP server ready on port " + launcher.getPort());
                System.out.println("Press Ctrl+C to stop");

                // Add shutdown hook for clean exit
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("\nShutting down...");
                    launcher.stop();
                }));

                // Keep running until interrupted
                try {
                    Thread.currentThread().join();
                } catch (InterruptedException e) {
                    // Normal exit
                }
            } else {
                System.err.println("Failed to start server within timeout");
                System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("Error starting server: " + e.getMessage());
            System.exit(1);
        }
    }
}
