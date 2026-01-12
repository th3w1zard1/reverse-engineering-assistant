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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;

/**
 * Tool provider for project-related operations.
 * Provides the get_current_context tool per new_tool_list.md spec.
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
        // GUI-only tool: requires ToolManager which isn't available in headless mode
        if (!headlessMode) {
            registerGetCurrentContextTool();
        }
    }

    /**
     * Register a tool to get the currently selected address or function in the Ghidra GUI
     */
    private void registerGetCurrentContextTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Context mode: 'address', 'function', or 'both'",
            "enum", List.of("address", "function", "both"),
            "default", "both"
        ));

        List<String> required = new ArrayList<>();

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get_current_context")
            .title("Get Current Context")
            .description("Get the address or function currently selected in the Ghidra GUI.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Get the active project
                Project project = AppInfo.getActiveProject();
                if (project == null) {
                    return createErrorResult("No active project found");
                }

                // Get the tool manager
                ToolManager toolManager = project.getToolManager();
                if (toolManager == null) {
                    return createErrorResult("No tool manager available (headless mode)");
                }

                // Find an active Code Browser tool
                PluginTool codeBrowserTool = null;
                PluginTool[] runningTools = toolManager.getRunningTools();

                for (PluginTool runningTool : runningTools) {
                    if ("CodeBrowser".equals(runningTool.getName())) {
                        ProgramManager programManager = runningTool.getService(ProgramManager.class);
                        if (programManager != null && programManager.getCurrentProgram() != null) {
                            codeBrowserTool = runningTool;
                            break;
                        }
                    }
                }

                if (codeBrowserTool == null) {
                    return createErrorResult("No active Code Browser tool found with an open program");
                }

                // Get the current program
                ProgramManager programManager = codeBrowserTool.getService(ProgramManager.class);
                Program currentProgram = programManager.getCurrentProgram();
                if (currentProgram == null) {
                    return createErrorResult("No program is currently active in Code Browser");
                }

                // Get current location from CodeViewerService
                ghidra.app.services.CodeViewerService codeViewerService =
                    codeBrowserTool.getService(ghidra.app.services.CodeViewerService.class);

                String mode = getOptionalString(request, "mode", "both");
                Map<String, Object> result = new HashMap<>();

                if (codeViewerService != null) {
                    ghidra.program.util.ProgramLocation currentLocation = codeViewerService.getCurrentLocation();
                    if (currentLocation != null) {
                        ghidra.program.model.address.Address currentAddress = currentLocation.getAddress();

                        if ("address".equals(mode) || "both".equals(mode)) {
                            result.put("address", reva.util.AddressUtil.formatAddress(currentAddress));
                            result.put("programPath", currentProgram.getDomainFile().getPathname());
                        }

                        if ("function".equals(mode) || "both".equals(mode)) {
                            ghidra.program.model.listing.Function function =
                                currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
                            if (function != null) {
                                Map<String, Object> functionInfo = new HashMap<>();
                                functionInfo.put("name", function.getName());
                                functionInfo.put("address", reva.util.AddressUtil.formatAddress(function.getEntryPoint()));
                                result.put("function", functionInfo);
                                result.put("programPath", currentProgram.getDomainFile().getPathname());
                            } else if ("function".equals(mode)) {
                                return createErrorResult("Current address is not within a function");
                            }
                        }
                    } else {
                        return createErrorResult("No current location available in Code Browser");
                    }
                } else {
                    // Fallback: try to get location from active program
                    // This is less accurate but works if CodeViewerService is not available
                    return createErrorResult("CodeViewerService not available in current tool");
                }

                result.put("success", true);
                return createJsonResult(result);
            } catch (Exception e) {
                logError("Error in get_current_context", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

}
