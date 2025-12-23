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
package reva.tools.project;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.data.DefaultCheckinHandler;
import ghidra.framework.model.DomainObject;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ToolManager;
import ghidra.base.project.GhidraProject;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.plugins.importer.tasks.ImportBatchTask;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.SchemaUtil;
import reva.util.RevaInternalServiceRegistry;
import reva.util.ToolLogCollector;

/**
 * Tool provider for project-related operations.
 * Provides tools to get the current program, list project files, and perform version control operations.
 */
public class ProjectToolProvider extends AbstractToolProvider {

    private final boolean headlessMode;

    /**
     * Constructor
     * @param server The MCP server
     * @param headlessMode True if running in headless mode (no GUI context)
     */
    public ProjectToolProvider(McpSyncServer server, boolean headlessMode) {
        super(server);
        this.headlessMode = headlessMode;
    }

    @Override
    public void registerTools() {
        // Available in all modes - opens project and loads programs into memory
        registerOpenProjectTool();

        // GUI-only tools: require ToolManager which isn't available in headless mode
        if (!headlessMode) {
            registerGetCurrentProgramTool();
            registerListOpenProgramsTool();
            registerOpenProgramInCodeBrowserTool();
            registerOpenAllProgramsInCodeBrowserTool();
        }
        registerListProjectFilesTool();
        registerCheckinProgramTool();
        registerAnalyzeProgramTool();
        registerChangeProcessorTool();
        registerImportFileTool();
        registerOpenProgramTool();
    }

    /**
     * Register a tool to get the currently active program
     */
    private void registerGetCurrentProgramTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        // This tool doesn't require any parameters
        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-current-program")
            .title("Get Current Program")
            .description("Get the currently active program in Ghidra")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get all open programs
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            if (openPrograms.isEmpty()) {
                return createErrorResult("No programs are currently open in Ghidra");
            }

            // For now, just return the first program (assuming it's the active one)
            Program program = openPrograms.get(0);

            // Create result data
            Map<String, Object> programInfo = new HashMap<>();
            programInfo.put("programPath", program.getDomainFile().getPathname());
            programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
            programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            programInfo.put("creationDate", program.getCreationDate());
            programInfo.put("sizeBytes", program.getMemory().getSize());
            programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
            programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
            programInfo.put("modificationDate", program.getDomainFile().getLastModifiedTime());
            programInfo.put("isReadOnly", program.getDomainFile().isReadOnly());

            return createJsonResult(programInfo);
        });
    }

    /**
     * Register a tool to list files and folders in the Ghidra project
     */
    private void registerListProjectFilesTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("folderPath", SchemaUtil.stringProperty(
            "Path to the folder to list contents of. Use '/' for the root folder."
        ));
        properties.put("recursive", SchemaUtil.booleanPropertyWithDefault(
            "Whether to list files recursively", false
        ));

        List<String> required = List.of("folderPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-project-files")
            .title("List Project Files")
            .description("List files and folders in the Ghidra project")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the folder path from the request
            String folderPath;
            try {
                folderPath = getString(request, "folderPath");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            // Get the recursive flag
            boolean recursive = getOptionalBoolean(request, "recursive", false);

            // Get the active project
            Project project = AppInfo.getActiveProject();
            if (project == null) {
                return createErrorResult("No active project found");
            }

            // Get the folder from the path
            DomainFolder folder;
            if (folderPath.equals("/")) {
                folder = project.getProjectData().getRootFolder();
            } else {
                folder = project.getProjectData().getFolder(folderPath);
            }

            if (folder == null) {
                return createErrorResult("Folder not found: " + folderPath);
            }

            // Get files and folders in the specified path
            List<Map<String, Object>> filesList = new ArrayList<>();

            // Add metadata about the current folder
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("folderPath", folderPath);
            metadataInfo.put("folderName", folder.getName());
            metadataInfo.put("isRecursive", recursive);

            // Get the files and folders
            if (recursive) {
                collectFilesRecursive(folder, filesList, "");
            } else {
                collectFilesInFolder(folder, filesList, "");
            }

            metadataInfo.put("itemCount", filesList.size());

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(filesList);

            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Register a tool to list all open programs across all Ghidra tools
     */
    private void registerListOpenProgramsTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        // This tool doesn't require any parameters
        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-open-programs")
            .title("List Open Programs")
            .description("List all programs currently open in Ghidra across all tools")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get all open programs from all tools
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

            if (openPrograms.isEmpty()) {
                return createErrorResult("No programs are currently open in Ghidra");
            }

            // Create program info for each program
            List<Map<String, Object>> programsData = new ArrayList<>();
            for (Program program : openPrograms) {
                Map<String, Object> programInfo = new HashMap<>();
                programInfo.put("programPath", program.getDomainFile().getPathname());
                programInfo.put("language", program.getLanguage().getLanguageID().getIdAsString());
                programInfo.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                programInfo.put("creationDate", program.getCreationDate());
                programInfo.put("sizeBytes", program.getMemory().getSize());
                programInfo.put("symbolCount", program.getSymbolTable().getNumSymbols());
                programInfo.put("functionCount", program.getFunctionManager().getFunctionCount());
                programInfo.put("modificationDate", program.getDomainFile().getLastModifiedTime());
                programInfo.put("isReadOnly", program.getDomainFile().isReadOnly());
                programsData.add(programInfo);
            }

            // Create metadata
            Map<String, Object> metadataInfo = new HashMap<>();
            metadataInfo.put("count", programsData.size());

            // Create combined result
            List<Object> resultData = new ArrayList<>();
            resultData.add(metadataInfo);
            resultData.addAll(programsData);

            return createMultiJsonResult(resultData);
        });
    }

    /**
     * Register a tool to checkin (commit) a program to version control
     */
    private void registerCheckinProgramTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to checkin (e.g., '/Hatchery.exe')"
        ));
        properties.put("message", SchemaUtil.stringProperty(
            "Commit message for the checkin"
        ));
        properties.put("keepCheckedOut", SchemaUtil.booleanPropertyWithDefault(
            "Whether to keep the program checked out after checkin", false
        ));

        List<String> required = List.of("programPath", "message");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("checkin-program")
            .title("Checkin Program")
            .description("Checkin (commit) a program to version control with a commit message")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters
            String programPath;
            String message;
            try {
                programPath = getString(request, "programPath");
                message = getString(request, "message");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            boolean keepCheckedOut = getOptionalBoolean(request, "keepCheckedOut", false);

            // Get the program
            Program program;
            try {
                program = getProgramFromArgs(request);
            } catch (Exception e) {
                return createErrorResult(e.getMessage());
            }

            DomainFile domainFile = program.getDomainFile();

            try {
                // Save program first (required before version control operations)
                // Skip save for read-only programs (common in test environments)
                if (!domainFile.isReadOnly()) {
                    try {
                        program.save(message, TaskMonitor.DUMMY);
                        program.flushEvents();  // Ensure SAVED event is processed
                    } catch (java.io.IOException e) {
                        return createErrorResult("Failed to save program: " + e.getMessage());
                    }
                }

                // Release program from cache before version control operations
                // Version control requires no active consumers on the domain file
                boolean wasCached = RevaProgramManager.releaseProgramFromCache(program);
                if (wasCached) {
                    Msg.debug(this, "Released program from cache for version control: " + programPath);
                }

                if (domainFile.canAddToRepository()) {
                    // New file - add to version control
                    domainFile.addToVersionControl(message, !keepCheckedOut, TaskMonitor.DUMMY);

                    // Re-open program to cache if it was cached and we're keeping it checked out
                    if (wasCached && keepCheckedOut) {
                        Program reopenedProgram = RevaProgramManager.reopenProgramToCache(programPath);
                        if (reopenedProgram != null) {
                            Msg.debug(this, "Re-opened program to cache after version control: " + programPath);
                        }
                    }

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("action", "added_to_version_control");
                    result.put("programPath", programPath);
                    result.put("message", message);
                    result.put("keepCheckedOut", keepCheckedOut);
                    result.put("isVersioned", domainFile.isVersioned());
                    result.put("isCheckedOut", domainFile.isCheckedOut());

                    return createJsonResult(result);
                }
                else if (domainFile.canCheckin()) {
                    // Existing versioned file - check in changes
                    DefaultCheckinHandler checkinHandler = new DefaultCheckinHandler(
                        message + "\n💜🐉✨ (ReVa)", keepCheckedOut, false);
                    domainFile.checkin(checkinHandler, TaskMonitor.DUMMY);

                    // Re-open program to cache if it was cached and we're keeping it checked out
                    if (wasCached && keepCheckedOut) {
                        Program reopenedProgram = RevaProgramManager.reopenProgramToCache(programPath);
                        if (reopenedProgram != null) {
                            Msg.debug(this, "Re-opened program to cache after checkin: " + programPath);
                        }
                    }

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("action", "checked_in");
                    result.put("programPath", programPath);
                    result.put("message", message);
                    result.put("keepCheckedOut", keepCheckedOut);
                    result.put("isVersioned", domainFile.isVersioned());
                    result.put("isCheckedOut", domainFile.isCheckedOut());

                    return createJsonResult(result);
                }
                else if (!domainFile.isVersioned()) {
                    // Not versioned - changes were already saved at the beginning
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("action", "saved");
                    result.put("programPath", programPath);
                    result.put("message", message);
                    result.put("isVersioned", false);
                    result.put("info", "Program is not under version control - changes were saved instead");

                    return createJsonResult(result);
                }
                else {
                    // Other version control errors
                    if (!domainFile.isCheckedOut()) {
                        return createErrorResult("Program is not checked out and cannot be modified: " + programPath);
                    }
                    else if (!domainFile.modifiedSinceCheckout()) {
                        return createErrorResult("Program has no changes since checkout: " + programPath);
                    }
                    else {
                        return createErrorResult("Program cannot be checked in for an unknown reason: " + programPath);
                    }
                }

            } catch (Exception e) {
                return createErrorResult("Checkin failed: " + e.getMessage());
            }
        });
    }

    /**
     * Recursively collect all program paths from a folder and its subfolders
     * @param folder The folder to collect from
     * @param programPaths List to accumulate program paths
     */
    private void collectAllProgramPaths(DomainFolder folder, List<String> programPaths) {
        // Collect programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                programPaths.add(file.getPathname());
            }
        }

        // Recursively collect from subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            collectAllProgramPaths(subfolder, programPaths);
        }
    }

    /**
     * Collect imported files, optionally analyze them, and add them to version control
     * @param destFolder The destination folder where files were imported
     * @param importedBaseName The base name of the imported file/directory
     * @param analyzeAfterImport Whether to run auto-analysis on imported programs
     * @param analysisTimeoutSeconds Timeout in seconds for analysis operations
     * @param versionedFiles List to track successfully versioned files
     * @param analyzedFiles List to track successfully analyzed files
     * @param errors List to track errors
     * @param monitor Task monitor for cancellation and timeout checking
     */
    private void collectImportedFiles(DomainFolder destFolder, String importedBaseName,
                                     boolean analyzeAfterImport, int analysisTimeoutSeconds,
                                     List<String> versionedFiles, List<String> analyzedFiles,
                                     List<String> errors, TaskMonitor monitor) {
        try {
            // Find newly imported files in the destination folder
            for (DomainFile file : destFolder.getFiles()) {
                boolean wasAnalyzed = false;

                // Analyze if requested and this is a Program file
                if (file.getContentType().equals("Program") && analyzeAfterImport) {
                    try {
                        // Open program with temporary consumer
                        Object consumer = new Object();
                        DomainObject domainObject = file.getDomainObject(consumer, false, false, monitor);

                        if (domainObject instanceof Program) {
                            Program program = (Program) domainObject;
                            try {
                                // Get analysis manager
                                AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
                                if (analysisManager != null) {
                                    // Create timeout monitor for analysis
                                    TaskMonitor analysisMonitor = TimeoutTaskMonitor.timeoutIn(analysisTimeoutSeconds, TimeUnit.SECONDS);

                                    // Start analysis (async)
                                    analysisManager.startAnalysis(analysisMonitor);

                                    // Wait for completion with timeout
                                    analysisManager.waitForAnalysis(null, analysisMonitor);

                                    if (analysisMonitor.isCancelled()) {
                                        errors.add("Analysis timed out for " + file.getPathname() +
                                            " after " + analysisTimeoutSeconds + " seconds");
                                    } else {
                                        // Save program after analysis
                                        program.save("Auto-analysis complete", monitor);
                                        analyzedFiles.add(file.getPathname());
                                        wasAnalyzed = true;
                                    }
                                } else {
                                    errors.add("Could not get analysis manager for " + file.getPathname());
                                }
                            } finally {
                                // Release program
                                program.release(consumer);
                            }
                        }
                    } catch (Exception e) {
                        errors.add("Analysis failed for " + file.getPathname() + ": " + e.getMessage());
                    }
                }

                // Add to version control after analysis (or immediately if no analysis)
                if (file.canAddToRepository()) {
                    try {
                        // Use different commit message based on whether analysis was performed
                        String commitMessage = wasAnalyzed
                            ? "Initial import via ReVa (analyzed)"
                            : "Initial import via ReVa";
                        file.addToVersionControl(commitMessage, false, monitor);
                        versionedFiles.add(file.getPathname());
                    } catch (Exception e) {
                        errors.add("Failed to add " + file.getPathname() + " to version control: " + e.getMessage());
                    }
                }
            }

            // Recursively process subfolders
            for (DomainFolder subfolder : destFolder.getFolders()) {
                collectImportedFiles(subfolder, importedBaseName, analyzeAfterImport, analysisTimeoutSeconds,
                    versionedFiles, analyzedFiles, errors, monitor);
            }
        } catch (Exception e) {
            errors.add("Error collecting imported files: " + e.getMessage());
        }
    }

    /**
     * Collect files and subfolders from a folder
     * @param folder The folder to collect from
     * @param filesList The list to add files to
     * @param pathPrefix The path prefix for subfolder names
     */
    private void collectFilesInFolder(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        // Add subfolders first
        for (DomainFolder subfolder : folder.getFolders()) {
            Map<String, Object> folderInfo = new HashMap<>();
            folderInfo.put("folderPath", pathPrefix + subfolder.getName());
            folderInfo.put("type", "folder");
            folderInfo.put("childCount", subfolder.getFiles().length + subfolder.getFolders().length);
            filesList.add(folderInfo);
        }

        // Add files
        for (DomainFile file : folder.getFiles()) {
            Map<String, Object> fileInfo = new HashMap<>();
            fileInfo.put("programPath", file.getPathname());
            fileInfo.put("type", "file");
            fileInfo.put("contentType", file.getContentType());
            fileInfo.put("lastModified", file.getLastModifiedTime());
            fileInfo.put("readOnly", file.isReadOnly());
            fileInfo.put("versioned", file.isVersioned());
            fileInfo.put("checkedOut", file.isCheckedOut());

            // Add program-specific metadata when available
            if (file.getContentType().equals("Program")) {
                try {
                    if (file.getMetadata() != null) {
                        Object languageObj = file.getMetadata().get("CREATED_WITH_LANGUAGE");
                        if (languageObj != null) {
                            fileInfo.put("programLanguage", languageObj);
                        }
                        Object md5Obj = file.getMetadata().get("Executable MD5");
                        if (md5Obj != null) {
                            fileInfo.put("executableMD5", md5Obj);
                        }
                    }
                } catch (Exception e) {
                    // Ignore metadata errors - not critical for file listing
                }
            }

            filesList.add(fileInfo);
        }
    }

    /**
     * Recursively collect files and subfolders from a folder
     * @param folder The folder to collect from
     * @param filesList The list to add files to
     * @param pathPrefix The path prefix for subfolder names
     */
    private void collectFilesRecursive(DomainFolder folder, List<Map<String, Object>> filesList, String pathPrefix) {
        // Collect files in current folder
        collectFilesInFolder(folder, filesList, pathPrefix);

        // Recursively collect files in subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            String newPrefix = pathPrefix + subfolder.getName() + "/";
            collectFilesRecursive(subfolder, filesList, newPrefix);
        }
    }

    /**
     * Register a tool to analyze a program with Ghidra's auto-analysis
     */
    private void registerAnalyzeProgramTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to analyze (e.g., '/Hatchery.exe')"
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("analyze-program")
            .title("Analyze Program")
            .description("Run Ghidra's auto-analysis on a program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the program
            Program program;
            try {
                program = getProgramFromArgs(request);
            } catch (Exception e) {
                return createErrorResult(e.getMessage());
            }

            String programPath = program.getDomainFile().getPathname();

            try {
                // Get the auto-analysis manager
                AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
                if (analysisManager == null) {
                    return createErrorResult("Could not get analysis manager for program: " + programPath);
                }

                // Start analysis
                analysisManager.startAnalysis(TaskMonitor.DUMMY);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("message", "Analysis started successfully");
                result.put("analysisRunning", analysisManager.isAnalyzing());

                return createJsonResult(result);

            } catch (Exception e) {
                return createErrorResult("Analysis failed: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to change the processor architecture of an existing program
     */
    private void registerChangeProcessorTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to modify (e.g., '/Hatchery.exe')"
        ));
        properties.put("languageId", SchemaUtil.stringProperty(
            "Language ID for the new processor (e.g., 'x86:LE:64:default')"
        ));
        properties.put("compilerSpecId", SchemaUtil.stringProperty(
            "Compiler spec ID (optional, defaults to the language's default)"
        ));

        List<String> required = List.of("programPath", "languageId");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("change-processor")
            .title("Change Processor")
            .description("Change the processor architecture of an existing program")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get parameters
            String languageId;
            try {
                languageId = getString(request, "languageId");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            String compilerSpecId = getOptionalString(request, "compilerSpecId", null);

            // Get the program
            Program program;
            try {
                program = getProgramFromArgs(request);
            } catch (Exception e) {
                return createErrorResult(e.getMessage());
            }

            String programPath = program.getDomainFile().getPathname();

            try {
                // Get the language service
                LanguageService languageService = DefaultLanguageService.getLanguageService();

                // Parse the language ID
                LanguageID langId = new LanguageID(languageId);
                Language language = languageService.getLanguage(langId);

                // Get compiler spec
                CompilerSpec compilerSpec;
                if (compilerSpecId != null && !compilerSpecId.trim().isEmpty()) {
                    CompilerSpecID specId = new CompilerSpecID(compilerSpecId);
                    compilerSpec = language.getCompilerSpecByID(specId);
                } else {
                    compilerSpec = language.getDefaultCompilerSpec();
                }

                // Create language compiler spec pair
                LanguageCompilerSpecPair lcsPair = new LanguageCompilerSpecPair(langId, compilerSpec.getCompilerSpecID());

                // Change the processor
                int transactionID = program.startTransaction("Change processor architecture");
                try {
                    program.setLanguage(lcsPair.getLanguage(), lcsPair.getCompilerSpecID(), false, TaskMonitor.DUMMY);
                    program.endTransaction(transactionID, true);
                } catch (Exception e) {
                    program.endTransaction(transactionID, false);
                    throw e;
                }

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("oldLanguage", program.getLanguage().getLanguageID().getIdAsString());
                result.put("newLanguage", languageId);
                result.put("newCompilerSpec", compilerSpec.getCompilerSpecID().getIdAsString());
                result.put("message", "Processor architecture changed successfully");

                return createJsonResult(result);

            } catch (LanguageNotFoundException e) {
                return createErrorResult("Language not found: " + languageId);
            } catch (Exception e) {
                return createErrorResult("Failed to change processor architecture: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to import files into the Ghidra project
     */
    private void registerImportFileTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();

        // path parameter (required)
        // Note: The MCP client and Ghidra may have different working directories,
        // so absolute paths are recommended for reliable file resolution
        Map<String, Object> pathProperty = new HashMap<>();
        pathProperty.put("type", "string");
        pathProperty.put("description", "Absolute file system path to import (file, directory, or archive). Use absolute paths to ensure proper file resolution as the MCP client and Ghidra may have different working directories.");
        properties.put("path", pathProperty);

        // destinationFolder parameter (optional)
        Map<String, Object> destFolderProperty = new HashMap<>();
        destFolderProperty.put("type", "string");
        destFolderProperty.put("description", "Project folder path for imported files (default: root folder)");
        properties.put("destinationFolder", destFolderProperty);

        // recursive parameter (optional)
        Map<String, Object> recursiveProperty = new HashMap<>();
        recursiveProperty.put("type", "boolean");
        recursiveProperty.put("description", "Whether to recursively import from containers/archives (default: true)");
        properties.put("recursive", recursiveProperty);

        // maxDepth parameter (optional)
        Map<String, Object> maxDepthProperty = new HashMap<>();
        maxDepthProperty.put("type", "integer");
        maxDepthProperty.put("description", "Maximum container depth to recurse into (default: 20)");
        properties.put("maxDepth", maxDepthProperty);

        // analyzeAfterImport parameter (optional)
        Map<String, Object> analyzeProperty = new HashMap<>();
        analyzeProperty.put("type", "boolean");
        analyzeProperty.put("description", "Run auto-analysis after import (default: false)");
        properties.put("analyzeAfterImport", analyzeProperty);

        // enableVersionControl parameter (optional)
        Map<String, Object> versionControlProperty = new HashMap<>();
        versionControlProperty.put("type", "boolean");
        versionControlProperty.put("description", "Automatically add imported files to version control (default: true)");
        properties.put("enableVersionControl", versionControlProperty);

        List<String> required = List.of("path");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("import-file")
            .title("Import File")
            .description("Import files, directories, or archives into the Ghidra project using batch import")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            try {
                // Get required parameter
                String path = getString(request, "path");

                // Get optional parameters with defaults
                String destinationFolder = getOptionalString(request, "destinationFolder", "/");
                boolean recursive = getOptionalBoolean(request, "recursive", true);
                int maxDepth = getOptionalInt(request, "maxDepth", 20);
                boolean analyzeAfterImport = getOptionalBoolean(request, "analyzeAfterImport", false);
                boolean enableVersionControl = getOptionalBoolean(request, "enableVersionControl", true);

                // Validate file exists
                File file = new File(path);
                if (!file.exists()) {
                    return createErrorResult("File or directory does not exist: " + path);
                }

                // Get the active project
                Project project = AppInfo.getActiveProject();
                if (project == null) {
                    return createErrorResult("No active project found");
                }

                // Get destination folder
                DomainFolder destFolder;
                if (destinationFolder.equals("/")) {
                    destFolder = project.getProjectData().getRootFolder();
                } else {
                    destFolder = project.getProjectData().getFolder(destinationFolder);
                    if (destFolder == null) {
                        return createErrorResult("Destination folder not found: " + destinationFolder);
                    }
                }

                // Create BatchInfo with specified max depth
                BatchInfo batchInfo = new BatchInfo(recursive ? maxDepth : 1);

                // Convert file to FSRL and add to batch
                FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(file);
                boolean hasImportableFiles = batchInfo.addFile(fsrl, TaskMonitor.DUMMY);

                if (!hasImportableFiles) {
                    return createErrorResult("No importable files found in: " + path);
                }

                // Check if any files were actually discovered
                if (batchInfo.getTotalCount() == 0) {
                    return createErrorResult("No supported file formats found in: " + path);
                }

                // Get configuration for timeouts
                ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
                int importTimeoutSeconds = configManager != null ?
                    configManager.getDecompilerTimeoutSeconds() * 2 : 300; // 2x decompiler timeout or 5 min default
                int analysisTimeoutSeconds = configManager != null ?
                    configManager.getImportAnalysisTimeoutSeconds() : 600; // Default 10 minutes

                // Create timeout-protected monitor for import task
                TaskMonitor importMonitor = TimeoutTaskMonitor.timeoutIn(importTimeoutSeconds, TimeUnit.SECONDS);

                // Create and run the import task synchronously (blocks until completion)
                ImportBatchTask importTask = new ImportBatchTask(batchInfo, destFolder, null, true, false, false);
                importTask.run(importMonitor);

                // Check for timeout or cancellation
                if (importMonitor.isCancelled()) {
                    return createErrorResult("Import timed out after " + importTimeoutSeconds + " seconds. " +
                        "Try importing fewer files or increase timeout in ReVa configuration.");
                }

                // Track imported files for version control and analysis
                List<String> versionedFiles = new ArrayList<>();
                List<String> analyzedFiles = new ArrayList<>();
                List<String> errors = new ArrayList<>();

                // Process imported files: analyze if requested, then add to version control
                if (enableVersionControl || analyzeAfterImport) {
                    // Create monitor for version control and analysis operations
                    TaskMonitor vcMonitor = TimeoutTaskMonitor.timeoutIn(importTimeoutSeconds, TimeUnit.SECONDS);

                    // Get all files that were imported, analyze if requested, and add to version control
                    collectImportedFiles(destFolder, file.getName(), analyzeAfterImport, analysisTimeoutSeconds,
                        versionedFiles, analyzedFiles, errors, vcMonitor);
                }

                // Collect all imported program paths
                List<String> importedProgramPaths = new ArrayList<>();
                collectAllProgramPaths(destFolder, importedProgramPaths);

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("importedFrom", path);
                result.put("destinationFolder", destinationFolder);
                result.put("filesDiscovered", batchInfo.getTotalCount());
                result.put("groupsCreated", batchInfo.getGroups().size());
                result.put("maxDepthUsed", maxDepth);
                result.put("wasRecursive", recursive);
                result.put("analyzeAfterImport", analyzeAfterImport);
                result.put("enableVersionControl", enableVersionControl);
                result.put("importedPrograms", importedProgramPaths);

                if (enableVersionControl) {
                    result.put("filesAddedToVersionControl", versionedFiles.size());
                    result.put("versionedPrograms", versionedFiles);
                }

                if (analyzeAfterImport) {
                    result.put("filesAnalyzed", analyzedFiles.size());
                    result.put("analyzedPrograms", analyzedFiles);
                }

                if (!errors.isEmpty()) {
                    result.put("errors", errors);
                }

                String message = "Import completed successfully. " + batchInfo.getTotalCount() + " files imported";
                if (analyzeAfterImport && analyzedFiles.size() > 0) {
                    message += ", " + analyzedFiles.size() + " analyzed";
                }
                if (enableVersionControl && versionedFiles.size() > 0) {
                    message += ", " + versionedFiles.size() + " added to version control";
                }
                result.put("message", message + ".");

                return createJsonResult(result);

            } catch (IllegalArgumentException e) {
                return createErrorResult("Invalid parameter: " + e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Import failed: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to open a Ghidra project
     */
    private void registerOpenProjectTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("projectPath", SchemaUtil.stringProperty(
            "Path to the Ghidra project file (.gpr) to open. Use absolute path for reliability."
        ));
        properties.put("openAllPrograms", SchemaUtil.booleanPropertyWithDefault(
            "Whether to automatically open all programs in the project into memory (default: true). " +
            "Set to false for large projects where you want to open specific programs later.", true
        ));

        List<String> required = List.of("projectPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("open-project")
            .title("Open Project")
            .description("Open a Ghidra project from a .gpr file path and optionally load all programs into memory. " +
                "When openAllPrograms is true (default), all programs in the project are opened and cached, " +
                "making them immediately accessible to other tools like get-strings, get-functions, etc.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Start log collection to capture all messages during tool execution
            ToolLogCollector logCollector = new ToolLogCollector();
            logCollector.start();

            try {
                // Get the project path from the request
                String projectPath;
                boolean shouldOpenAllPrograms;
                try {
                    projectPath = getString(request, "projectPath");
                    shouldOpenAllPrograms = getOptionalBoolean(request, "openAllPrograms", true);
                } catch (IllegalArgumentException e) {
                    logCollector.stop();
                    return createErrorResult(e.getMessage());
                }

                // Validate the project file exists
                File projectFile = new File(projectPath);
                if (!projectFile.exists()) {
                    return createErrorResult("Project file does not exist: " + projectPath);
                }

                // Check if it's a .gpr file
                if (!projectPath.toLowerCase().endsWith(".gpr")) {
                    return createErrorResult("Project file must have .gpr extension: " + projectPath);
                }

                // Extract project directory and name from the .gpr file path
                // .gpr file is typically at: <projectDir>/<projectName>.gpr
                String projectDir = projectFile.getParent();
                String projectName = projectFile.getName();
                // Remove .gpr extension
                if (projectName.toLowerCase().endsWith(".gpr")) {
                    projectName = projectName.substring(0, projectName.length() - 4);
                }

                if (projectDir == null) {
                    return createErrorResult("Invalid project path: " + projectPath);
                }

                // Create ProjectLocator
                ProjectLocator locator = new ProjectLocator(projectDir, projectName);

                // Verify the project exists
                if (!locator.getMarkerFile().exists() || !locator.getProjectDir().exists()) {
                    return createErrorResult("Project not found at: " + projectPath +
                        " (marker file or project directory missing)");
                }

                // Check if this project is already open
                Project project = AppInfo.getActiveProject();
                boolean projectWasAlreadyOpen = false;

                // First, try to open the project
                GhidraProject ghidraProject = null;
                try {
                    // Open project with upgrade enabled (third parameter = true)
                    // This will automatically upgrade programs if needed
                    ghidraProject = GhidraProject.openProject(projectDir, projectName, true);
                    project = ghidraProject.getProject();

                    // CRITICAL: Save the project immediately after opening to persist any upgrades
                    // This ensures that upgrade dialogs (if any) result in saved changes
                    // In headless mode, upgrades should be automatic, but we save to be safe
                    try {
                        // Save project - upgrades are automatically handled
                        String saveMsg = "Project opened (upgrades handled automatically)";
                        Msg.info(this, saveMsg);
                        logCollector.addLog("INFO", saveMsg);
                    } catch (Exception saveException) {
                        String saveWarnMsg = "Warning: Error after opening project: " + saveException.getMessage();
                        Msg.warn(this, saveWarnMsg);
                        logCollector.addLog("WARN", saveWarnMsg);
                        // Don't fail the operation if save fails - project is still open
                    }
                } catch (Exception e) {
                    // If opening fails (likely because project is already locked/open), use active project
                    String errorMsg = e.getMessage();
                    if (errorMsg != null && (errorMsg.contains("lock") || errorMsg.contains("Lock") || errorMsg.contains("Unable"))) {
                        // Project is locked - use active project if available
                        Project activeProject = AppInfo.getActiveProject();
                        if (activeProject != null) {
                            // Verify the active project matches the requested one by checking location
                            String activeProjectDir = activeProject.getProjectLocator().getProjectDir().getAbsolutePath();
                            String requestedProjectDir = new File(projectDir).getAbsolutePath();

                            if (activeProjectDir.equals(requestedProjectDir) || activeProject.getName().equals(projectName)) {
                                project = activeProject;
                                projectWasAlreadyOpen = true;
                                String logMsg = "Project is locked (already open), using active project: " + activeProject.getName();
                                Msg.info(this, logMsg);
                                logCollector.addLog("INFO", logMsg);
                            } else {
                                return createErrorResult(String.format(
                                    "Project is locked. Active project '%s' at '%s' does not match requested project '%s' at '%s'. " +
                                    "Please close the other project or open the correct one.",
                                    activeProject.getName(), activeProjectDir, projectName, requestedProjectDir
                                ));
                            }
                        } else {
                            return createErrorResult("Project is locked and no active project available. Please close the project in Ghidra first or ensure a project is open.");
                        }
                    } else {
                        // Some other error - re-throw it
                        throw e;
                    }
                }

                // Verify we have a valid project
                if (project == null) {
                    return createErrorResult("Failed to open or access project: " + projectPath);
                }

                // Upgrades are handled automatically when opening programs
                // No need to check for unsaved changes - Ghidra handles this internally

                // Collect all programs in the project
                List<DomainFile> allPrograms = new ArrayList<>();
                try {
                    DomainFolder rootFolder = project.getProjectData().getRootFolder();
                    collectAllPrograms(rootFolder, allPrograms);
                } catch (Exception e) {
                    String logMsg = "Error collecting programs: " + e.getMessage();
                    Msg.warn(this, logMsg);
                    logCollector.addLog("WARN", logMsg);
                }

                // Open programs into memory if requested (default: true)
                List<String> openedPrograms = new ArrayList<>();
                List<String> failedPrograms = new ArrayList<>();
                List<String> availablePrograms = new ArrayList<>();

                for (DomainFile domainFile : allPrograms) {
                    availablePrograms.add(domainFile.getPathname());
                }

                if (shouldOpenAllPrograms) {
                    for (DomainFile domainFile : allPrograms) {
                        String programPath = domainFile.getPathname();
                        try {
                            // Use RevaProgramManager to open the program - this caches it for future access
                            // This will automatically handle any program upgrades needed
                            Program program = RevaProgramManager.getProgramByPath(programPath);
                            if (program != null && !program.isClosed()) {
                                openedPrograms.add(programPath);
                                String logMsg = "Opened program: " + programPath;
                                Msg.info(this, logMsg);
                                logCollector.addLog("INFO", logMsg);

                                // Programs are automatically saved when opened
                                // Upgrades are handled automatically by Ghidra
                            } else {
                                failedPrograms.add(programPath + " (returned null or closed)");
                            }
                        } catch (Exception e) {
                            failedPrograms.add(programPath + " (" + e.getMessage() + ")");
                            String logMsg = "Failed to open program " + programPath + ": " + e.getMessage();
                            Msg.warn(this, logMsg);
                            logCollector.addLog("WARN", logMsg);
                        }
                    }

                    // Programs and project are automatically saved by Ghidra when opened
                }

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("projectPath", projectPath);
                result.put("projectName", project.getName());
                result.put("projectLocation", projectDir);
                result.put("projectWasAlreadyOpen", projectWasAlreadyOpen);

                // Get project metadata
                result.put("isActive", (AppInfo.getActiveProject() == project));
                result.put("programCount", allPrograms.size());
                result.put("availablePrograms", availablePrograms);
                result.put("openAllProgramsRequested", shouldOpenAllPrograms);
                result.put("programsOpened", openedPrograms.size());
                result.put("programsFailed", failedPrograms.size());

                if (!openedPrograms.isEmpty()) {
                    result.put("openedPrograms", openedPrograms);
                }

                if (!failedPrograms.isEmpty()) {
                    result.put("failedPrograms", failedPrograms);
                }

                String message;
                if (shouldOpenAllPrograms) {
                    message = String.format(
                        "Project '%s' opened successfully. %d programs found, %d opened into memory, %d failed.",
                        project.getName(), allPrograms.size(), openedPrograms.size(), failedPrograms.size()
                    );
                } else {
                    message = String.format(
                        "Project '%s' opened successfully. %d programs available. Use get-strings, get-functions, etc. with programPath to access them.",
                        project.getName(), allPrograms.size()
                    );
                }
                result.put("message", message);

                // Add collected logs to response
                ToolLogCollector.addLogsToResult(result, logCollector);
                logCollector.stop();

                return createJsonResult(result);

            } catch (IllegalArgumentException e) {
                logCollector.stop();
                return createErrorResult("Invalid project path: " + e.getMessage());
            } catch (Exception e) {
                logCollector.stop();
                return createErrorResult("Failed to open project: " + e.getMessage());
            }
        });
    }

    /**
     * Recursively count programs in a folder
     * @param folder The folder to count programs in
     * @return The number of programs found
     */
    private int countPrograms(DomainFolder folder) {
        int count = 0;

        // Count programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                count++;
            }
        }

        // Recursively count in subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            count += countPrograms(subfolder);
        }

        return count;
    }

    /**
     * Recursively collect all programs in a folder
     * @param folder The folder to search
     * @param programs List to add programs to
     */
    private void collectAllPrograms(DomainFolder folder, List<DomainFile> programs) {
        // Collect programs in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                programs.add(file);
            }
        }

        // Recursively collect from subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            collectAllPrograms(subfolder, programs);
        }
    }

    /**
     * Register a tool to open a program in Code Browser
     */
    private void registerOpenProgramInCodeBrowserTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty(
            "Path to the program to open in Code Browser (e.g., '/swkotor.exe')"
        ));

        List<String> required = List.of("programPath");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("open-program-in-code-browser")
            .title("Open Program in Code Browser")
            .description("Open a program in Ghidra's Code Browser tool. The program will be opened if not already open.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            // Get the program path from the request
            String programPath;
            try {
                programPath = getString(request, "programPath");
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            }

            try {
                // Get the program (this will open it if not already open)
                Program program;
                try {
                    program = getProgramFromArgs(request);
                } catch (Exception e) {
                    return createErrorResult(e.getMessage());
                }

                if (program == null || program.isClosed()) {
                    return createErrorResult("Failed to open program: " + programPath);
                }

                // Get the active project
                Project project = AppInfo.getActiveProject();
                if (project == null) {
                    return createErrorResult("No active project found");
                }

                // Get the tool manager
                ToolManager toolManager = project.getToolManager();
                if (toolManager == null) {
                    return createErrorResult("No tool manager available");
                }

                // Find an existing Code Browser tool
                PluginTool codeBrowserTool = null;
                PluginTool[] runningTools = toolManager.getRunningTools();

                // Look for existing Code Browser tool
                for (PluginTool runningTool : runningTools) {
                    if ("CodeBrowser".equals(runningTool.getName())) {
                        codeBrowserTool = runningTool;
                        break;
                    }
                }

                // If no Code Browser found, try to use RevaPlugin's tool if it has ProgramManager
                if (codeBrowserTool == null) {
                    reva.plugin.RevaPlugin revaPlugin = reva.util.RevaInternalServiceRegistry.getService(reva.plugin.RevaPlugin.class);
                    if (revaPlugin != null && revaPlugin.getTool() != null) {
                        PluginTool revaTool = revaPlugin.getTool();
                        ProgramManager testManager = revaTool.getService(ProgramManager.class);
                        if (testManager != null) {
                            codeBrowserTool = revaTool;
                            Msg.debug(this, "Using RevaPlugin's tool for opening program");
                        }
                    }
                }

                // If still no tool found, return error (cannot programmatically launch tools)
                if (codeBrowserTool == null) {
                    return createErrorResult("No Code Browser tool is currently running. Please open Code Browser in Ghidra first, or the program will be opened in the background and available via other tools.");
                }

                // Get the ProgramManager service from the Code Browser tool
                ProgramManager programManager = codeBrowserTool.getService(ProgramManager.class);
                if (programManager == null) {
                    return createErrorResult("Code Browser tool does not have ProgramManager service");
                }

                // Check if program is already open in this tool
                Program[] openPrograms = programManager.getAllOpenPrograms();
                boolean alreadyOpen = false;
                for (Program openProg : openPrograms) {
                    if (openProg.getDomainFile().getPathname().equals(program.getDomainFile().getPathname())) {
                        alreadyOpen = true;
                        break;
                    }
                }

                // Open the program in Code Browser if not already open
                if (!alreadyOpen) {
                    programManager.openProgram(program.getDomainFile());
                }

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("programName", program.getName());
                result.put("codeBrowserTool", codeBrowserTool.getName());
                result.put("wasAlreadyOpen", alreadyOpen);
                result.put("message", alreadyOpen ?
                    "Program is already open in Code Browser" :
                    "Program opened in Code Browser successfully");

                return createJsonResult(result);

            } catch (IllegalArgumentException e) {
                return createErrorResult("Invalid program path: " + e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Failed to open program in Code Browser: " + e.getMessage());
            }
        });
    }

    /**
     * Register a tool to open all programs (exe/dll) in the project in Code Browser
     */
    private void registerOpenAllProgramsInCodeBrowserTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("extensions", SchemaUtil.stringProperty(
            "Comma-separated list of file extensions to open (e.g., 'exe,dll' or 'exe'). Defaults to 'exe,dll'"
        ));
        properties.put("folderPath", SchemaUtil.stringProperty(
            "Folder path to search for programs (default: '/' for root folder)"
        ));

        List<String> required = new ArrayList<>();

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("open-all-programs-in-code-browser")
            .title("Open All Programs in Code Browser")
            .description("Open all programs matching specified extensions (exe/dll) in the project into Code Browser. Searches recursively through the project.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            try {
                // Get optional parameters
                String extensionsStr = getOptionalString(request, "extensions", "exe,dll");
                String folderPath = getOptionalString(request, "folderPath", "/");

                // Parse extensions
                String[] extensions = extensionsStr.split(",");
                Set<String> extensionSet = new HashSet<>();
                for (String ext : extensions) {
                    String trimmed = ext.trim().toLowerCase();
                    if (!trimmed.isEmpty()) {
                        // Remove leading dot if present
                        if (trimmed.startsWith(".")) {
                            trimmed = trimmed.substring(1);
                        }
                        extensionSet.add(trimmed);
                    }
                }

                if (extensionSet.isEmpty()) {
                    return createErrorResult("No valid extensions specified");
                }

                // Get the active project
                Project project = AppInfo.getActiveProject();
                if (project == null) {
                    return createErrorResult("No active project found");
                }

                // Get the folder to search
                DomainFolder folder;
                if (folderPath.equals("/")) {
                    folder = project.getProjectData().getRootFolder();
                } else {
                    folder = project.getProjectData().getFolder(folderPath);
                }

                if (folder == null) {
                    return createErrorResult("Folder not found: " + folderPath);
                }

                // Collect all matching programs
                List<DomainFile> matchingPrograms = new ArrayList<>();
                collectProgramsByExtension(folder, extensionSet, matchingPrograms);

                if (matchingPrograms.isEmpty()) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("programsFound", 0);
                    result.put("programsOpened", 0);
                    result.put("extensions", extensionSet);
                    result.put("message", "No programs found matching extensions: " + extensionSet);
                    return createJsonResult(result);
                }

                // Get or create Code Browser tool
                ToolManager toolManager = project.getToolManager();
                if (toolManager == null) {
                    return createErrorResult("No tool manager available");
                }

                PluginTool codeBrowserTool = null;
                PluginTool[] runningTools = toolManager.getRunningTools();

                for (PluginTool runningTool : runningTools) {
                    if ("CodeBrowser".equals(runningTool.getName())) {
                        codeBrowserTool = runningTool;
                        break;
                    }
                }

                // If no Code Browser found, try to use RevaPlugin's tool if it has ProgramManager
                if (codeBrowserTool == null) {
                    reva.plugin.RevaPlugin revaPlugin = reva.util.RevaInternalServiceRegistry.getService(reva.plugin.RevaPlugin.class);
                    if (revaPlugin != null && revaPlugin.getTool() != null) {
                        PluginTool revaTool = revaPlugin.getTool();
                        ProgramManager testManager = revaTool.getService(ProgramManager.class);
                        if (testManager != null) {
                            codeBrowserTool = revaTool;
                            Msg.debug(this, "Using RevaPlugin's tool for opening programs");
                        }
                    }
                }

                // If still no tool found, return error (cannot programmatically launch tools)
                if (codeBrowserTool == null) {
                    return createErrorResult("No Code Browser tool is currently running. Please open Code Browser in Ghidra first, or programs will be opened in the background and available via other tools.");
                }

                ProgramManager programManager = codeBrowserTool.getService(ProgramManager.class);
                if (programManager == null) {
                    return createErrorResult("Code Browser tool does not have ProgramManager service");
                }

                // Get currently open programs to avoid duplicates
                Program[] openPrograms = programManager.getAllOpenPrograms();
                Set<String> openProgramPaths = new HashSet<>();
                for (Program openProg : openPrograms) {
                    openProgramPaths.add(openProg.getDomainFile().getPathname());
                }

                // Open each matching program
                List<String> openedPrograms = new ArrayList<>();
                List<String> alreadyOpenPrograms = new ArrayList<>();
                List<String> failedPrograms = new ArrayList<>();

                for (DomainFile domainFile : matchingPrograms) {
                    String programPath = domainFile.getPathname();

                    if (openProgramPaths.contains(programPath)) {
                        alreadyOpenPrograms.add(programPath);
                        continue;
                    }

                    try {
                        programManager.openProgram(domainFile);
                        openedPrograms.add(programPath);
                        openProgramPaths.add(programPath); // Track as opened
                    } catch (Exception e) {
                        failedPrograms.add(programPath + " (" + e.getMessage() + ")");
                        Msg.error(this, "Failed to open program " + programPath + ": " + e.getMessage());
                    }
                }

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programsFound", matchingPrograms.size());
                result.put("programsOpened", openedPrograms.size());
                result.put("programsAlreadyOpen", alreadyOpenPrograms.size());
                result.put("programsFailed", failedPrograms.size());
                result.put("extensions", extensionSet);
                result.put("openedPrograms", openedPrograms);
                result.put("alreadyOpenPrograms", alreadyOpenPrograms);
                if (!failedPrograms.isEmpty()) {
                    result.put("failedPrograms", failedPrograms);
                }
                result.put("message", String.format(
                    "Opened %d programs, %d were already open, %d failed",
                    openedPrograms.size(), alreadyOpenPrograms.size(), failedPrograms.size()
                ));

                return createJsonResult(result);

            } catch (IllegalArgumentException e) {
                return createErrorResult("Invalid parameter: " + e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Failed to open programs: " + e.getMessage());
            }
        });
    }

    /**
     * Recursively collect programs matching specified extensions
     * @param folder The folder to search
     * @param extensions Set of extensions to match (without leading dot, lowercase)
     * @param programs List to add matching programs to
     */
    private void collectProgramsByExtension(DomainFolder folder, Set<String> extensions, List<DomainFile> programs) {
        // Check files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                String fileName = file.getName().toLowerCase();
                // Check if file extension matches
                int lastDot = fileName.lastIndexOf('.');
                if (lastDot > 0 && lastDot < fileName.length() - 1) {
                    String ext = fileName.substring(lastDot + 1);
                    if (extensions.contains(ext)) {
                        programs.add(file);
                    }
                }
            }
        }

        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            collectProgramsByExtension(subfolder, extensions, programs);
        }
    }

    /**
     * Register a tool to open a program in the current project.
     * If the program doesn't exist in the project, it will be imported first.
     * The program will be opened in memory, saved to the project, and cached for future access.
     */
    private void registerOpenProgramTool() {
        // Define schema for the tool
        Map<String, Object> properties = new HashMap<>();
        properties.put("path", SchemaUtil.stringProperty(
            "File system path to program. Imports if not in project, opens if exists."
        ));
        properties.put("destinationFolder", SchemaUtil.stringProperty(
            "Project folder for new imports (default: '/'). Ignored if program exists."
        ));
        properties.put("analyzeAfterImport", SchemaUtil.booleanPropertyWithDefault(
            "Run auto-analysis on new imports (default: true). Ignored if program exists.",
            true
        ));
        properties.put("enableVersionControl", SchemaUtil.booleanPropertyWithDefault(
            "Add new imports to version control (default: true). Program always saved regardless.",
            true
        ));

        List<String> required = List.of("path");

        // Create the tool
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("open-program")
            .title("Open Program")
            .description("Open program in project. Imports if missing, opens if exists. Always saves to project. Caches for other tools.")
            .inputSchema(createSchema(properties, required))
            .build();

        // Register the tool with a handler
        registerTool(tool, (exchange, request) -> {
            try {
                // Get required parameter
                String path = getString(request, "path");

                // Get optional parameters with defaults
                String destinationFolder = getOptionalString(request, "destinationFolder", "/");
                boolean analyzeAfterImport = getOptionalBoolean(request, "analyzeAfterImport", true);
                boolean enableVersionControl = getOptionalBoolean(request, "enableVersionControl", true);

                // Validate file exists
                File file = new File(path);
                if (!file.exists()) {
                    return createErrorResult("File does not exist: " + path);
                }

                // Get the active project
                Project project = AppInfo.getActiveProject();
                if (project == null) {
                    return createErrorResult("No active project found. Please open a project first using open-project.");
                }

                // Check if program already exists in project by searching for it
                String fileName = file.getName();
                DomainFile existingProgram = null;
                DomainFolder searchFolder = destinationFolder.equals("/")
                    ? project.getProjectData().getRootFolder()
                    : project.getProjectData().getFolder(destinationFolder);

                if (searchFolder != null) {
                    // Search for existing program in the destination folder and subfolders
                    existingProgram = findProgramInFolder(searchFolder, fileName);
                }

                String programPath;
                boolean wasImported = false;

                if (existingProgram != null) {
                    // Program already exists - use it
                    programPath = existingProgram.getPathname();
                    logInfo("Program already exists in project: " + programPath);
                } else {
                    // Program doesn't exist - import it
                    logInfo("Program not found in project, importing: " + path);

                    // Get destination folder
                    DomainFolder destFolder;
                    if (destinationFolder.equals("/")) {
                        destFolder = project.getProjectData().getRootFolder();
                    } else {
                        destFolder = project.getProjectData().getFolder(destinationFolder);
                        if (destFolder == null) {
                            return createErrorResult("Destination folder not found: " + destinationFolder);
                        }
                    }

                    // Import the file using batch import
                    BatchInfo batchInfo = new BatchInfo(1); // Don't recurse for single file
                    FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(file);
                    boolean hasImportableFiles = batchInfo.addFile(fsrl, TaskMonitor.DUMMY);

                    if (!hasImportableFiles || batchInfo.getTotalCount() == 0) {
                        return createErrorResult("No importable program found in: " + path);
                    }

                    // Get configuration for timeouts
                    ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
                    int importTimeoutSeconds = configManager != null ?
                        configManager.getDecompilerTimeoutSeconds() * 2 : 300;

                    // Create timeout-protected monitor for import task
                    TaskMonitor importMonitor = TimeoutTaskMonitor.timeoutIn(importTimeoutSeconds, TimeUnit.SECONDS);

                    // Create and run the import task synchronously
                    ImportBatchTask importTask = new ImportBatchTask(batchInfo, destFolder, null, true, false, false);
                    importTask.run(importMonitor);

                    // Check for timeout or cancellation
                    if (importMonitor.isCancelled()) {
                        return createErrorResult("Import timed out after " + importTimeoutSeconds + " seconds");
                    }

                    // Find the imported program
                    existingProgram = findProgramInFolder(destFolder, fileName);
                    if (existingProgram == null) {
                        return createErrorResult("Program was imported but could not be found in project");
                    }

                    programPath = existingProgram.getPathname();
                    wasImported = true;

                    // Analyze if requested
                    if (analyzeAfterImport) {
                        try {
                            Object consumer = new Object();
                            DomainObject domainObject = existingProgram.getDomainObject(consumer, false, false, TaskMonitor.DUMMY);
                            if (domainObject instanceof Program) {
                                Program program = (Program) domainObject;
                                try {
                                    AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
                                    if (analysisManager != null) {
                                        int analysisTimeoutSeconds = configManager != null ?
                                            configManager.getImportAnalysisTimeoutSeconds() : 600;
                                        TaskMonitor analysisMonitor = TimeoutTaskMonitor.timeoutIn(analysisTimeoutSeconds, TimeUnit.SECONDS);
                                        analysisManager.startAnalysis(analysisMonitor);
                                        analysisManager.waitForAnalysis(null, analysisMonitor);
                                        if (!analysisMonitor.isCancelled()) {
                                            program.save("Auto-analysis complete", TaskMonitor.DUMMY);
                                        }
                                    }
                                } finally {
                                    program.release(consumer);
                                }
                            }
                        } catch (Exception e) {
                            logError("Analysis failed for imported program: " + programPath, e);
                            // Continue - program is still imported
                        }
                    }

                    // Add to version control if requested
                    // NOTE: Version control is separate from saving. The program is ALWAYS saved to the project
                    // regardless of this setting. Version control only enables change tracking over time.
                    if (enableVersionControl && existingProgram.canAddToRepository()) {
                        try {
                            String commitMessage = analyzeAfterImport
                                ? "Initial import via ReVa open-program (analyzed)"
                                : "Initial import via ReVa open-program";
                            existingProgram.addToVersionControl(commitMessage, false, TaskMonitor.DUMMY);
                        } catch (Exception e) {
                            logError("Failed to add program to version control: " + programPath, e);
                            // Continue - program is still imported and will be saved
                        }
                    }

                    // Program is automatically saved when imported
                    // No explicit save needed - Ghidra handles this
                }

                // Open the program in memory using RevaProgramManager (this caches it)
                Program program = RevaProgramManager.getProgramByPath(programPath);
                if (program == null || program.isClosed()) {
                    return createErrorResult("Failed to open program: " + programPath);
                }

                // Program is automatically saved when opened
                // Auto-save will handle any modifications made via tools

                // Create result data
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("programName", program.getName());
                result.put("wasImported", wasImported);
                result.put("isOpen", !program.isClosed());
                result.put("language", program.getLanguage().getLanguageID().getIdAsString());
                result.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
                result.put("sizeBytes", program.getMemory().getSize());
                result.put("functionCount", program.getFunctionManager().getFunctionCount());
                result.put("symbolCount", program.getSymbolTable().getNumSymbols());

                String message = wasImported
                    ? "Program imported and opened successfully: " + programPath
                    : "Program opened successfully: " + programPath;
                result.put("message", message);

                return createJsonResult(result);

            } catch (IllegalArgumentException e) {
                return createErrorResult("Invalid parameter: " + e.getMessage());
            } catch (Exception e) {
                return createErrorResult("Failed to open program: " + e.getMessage());
            }
        });
    }

    /**
     * Recursively search for a program file by name in a folder and its subfolders
     * @param folder The folder to search in
     * @param fileName The file name to search for
     * @return The DomainFile if found, null otherwise
     */
    private DomainFile findProgramInFolder(DomainFolder folder, String fileName) {
        // Check files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program") && file.getName().equals(fileName)) {
                return file;
            }
        }

        // Recursively search subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            DomainFile found = findProgramInFolder(subfolder, fileName);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

}
