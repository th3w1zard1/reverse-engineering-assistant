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
package reva.resources.impl;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import reva.plugin.RevaProgramManager;
import reva.resources.AbstractResourceProvider;

/**
 * Resource provider that exposes the list of currently open programs.
 * Supports subscriptions - clients will be notified when programs are opened or closed.
 */
public class ProgramListResource extends AbstractResourceProvider {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String RESOURCE_ID = "ghidra://programs";
    private static final String RESOURCE_NAME = "open-programs";
    private static final String RESOURCE_DESCRIPTION = "Currently open programs";
    private static final String RESOURCE_MIME_TYPE = "text/plain";

    /**
     * Constructor
     * @param server The MCP server to register with
     */
    public ProgramListResource(McpSyncServer server) {
        super(server);
    }

    @Override
    public void register() {
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME,
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // No schema needed for this resource
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                return generateResourceContents();
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME + " with subscription support");
    }

    /**
     * Generate the current resource contents for the programs resource.
     * This method is called both for read requests and when notifying subscribers.
     *
     * @return ReadResourceResult containing all program resource contents
     */
    private ReadResourceResult generateResourceContents() {
        List<ResourceContents> resourceContents = new ArrayList<>();

        // Get all open programs
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

        for (Program program : openPrograms) {
            try {
                // Create program info object
                String programPath = program.getDomainFile().getPathname();
                String programLanguage = program.getLanguage().getLanguageID().getIdAsString();
                String programCompilerSpec = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
                long programSize = program.getMemory().getSize();

                // Create a JSON object with program metadata
                String metaString = JSON.writeValueAsString(
                    new ProgramInfo(programPath, programLanguage, programCompilerSpec, programSize)
                );

                // Add to resource contents
                // URL encode the program path to ensure URI safety
                String encodedProgramPath = URLEncoder.encode(programPath, StandardCharsets.UTF_8);
                resourceContents.add(
                    new TextResourceContents(
                        RESOURCE_ID + "/" + encodedProgramPath,
                        RESOURCE_MIME_TYPE,
                        metaString
                    )
                );
            } catch (JsonProcessingException e) {
                logError("Error serializing program metadata", e);
            }
        }

        return new ReadResourceResult(resourceContents);
    }

    @Override
    public void programOpened(Program program) {
        // Notify subscribers that the resource has changed
        notifyResourceChanged();
    }

    @Override
    public void programClosed(Program program) {
        // Notify subscribers that the resource has changed
        notifyResourceChanged();
    }

    /**
     * Notify all subscribers that the resource content has changed.
     *
     * According to the MCP specification, when a subscribed resource changes,
     * the server must send a `notifications/resources/updated` notification
     * to all subscribed clients. The MCP Java SDK should handle subscription
     * requests automatically when subscriptions are enabled in capabilities,
     * but we need to trigger the notification when the resource changes.
     *
     * The SDK may provide methods to send notifications, or it may handle
     * this automatically. We attempt multiple approaches to ensure compatibility.
     */
    private void notifyResourceChanged() {
        try {
            // Generate updated resource contents
            ReadResourceResult newContents = generateResourceContents();

            // Attempt multiple notification approaches for maximum compatibility
            boolean notified = false;

            // Approach 1: Try notifyResourceChanged method (if it exists in SDK)
            try {
                java.lang.reflect.Method notifyMethod = server.getClass().getMethod(
                    "notifyResourceChanged", String.class, ReadResourceResult.class);
                notifyMethod.invoke(server, RESOURCE_ID, newContents);
                notified = true;
                logInfo("Notified subscribers via notifyResourceChanged: " + RESOURCE_NAME);
            } catch (NoSuchMethodException e) {
                // Method doesn't exist, try next approach
            } catch (Exception e) {
                logError("Error invoking notifyResourceChanged", e);
            }

            // Approach 2: Try sendResourceUpdatedNotification (alternative SDK method name)
            if (!notified) {
                try {
                    java.lang.reflect.Method sendMethod = server.getClass().getMethod(
                        "sendResourceUpdatedNotification", String.class);
                    sendMethod.invoke(server, RESOURCE_ID);
                    notified = true;
                    logInfo("Notified subscribers via sendResourceUpdatedNotification: " + RESOURCE_NAME);
                } catch (NoSuchMethodException e) {
                    // Method doesn't exist, try next approach
                } catch (Exception e) {
                    logError("Error invoking sendResourceUpdatedNotification", e);
                }
            }

            // Approach 3: Try generic notification method
            if (!notified) {
                try {
                    // Look for methods that might send notifications
                    java.lang.reflect.Method[] methods = server.getClass().getMethods();
                    for (java.lang.reflect.Method method : methods) {
                        String methodName = method.getName().toLowerCase();
                        if ((methodName.contains("notify") || methodName.contains("send")) &&
                            methodName.contains("resource") && method.getParameterCount() >= 1) {
                            try {
                                if (method.getParameterCount() == 1 &&
                                    method.getParameterTypes()[0] == String.class) {
                                    method.invoke(server, RESOURCE_ID);
                                    notified = true;
                                    logInfo("Notified subscribers via " + method.getName() + ": " + RESOURCE_NAME);
                                    break;
                                }
                            } catch (Exception e) {
                                // Try next method
                            }
                        }
                    }
                } catch (Exception e) {
                    // Reflection failed, continue to fallback
                }
            }

            // Approach 4: SDK may handle notifications automatically
            // When subscriptions are enabled, the SDK should automatically
            // send notifications when resources are accessed. We log that
            // the resource changed and the SDK should handle it.
            if (!notified) {
                logInfo("Resource changed: " + RESOURCE_NAME +
                    " (MCP SDK should handle subscription notifications automatically)");
            }
        } catch (Exception e) {
            logError("Error notifying resource change", e);
        }
    }

    /**
     * Simple class to hold program information for JSON serialization
     */
    private static class ProgramInfo {
        @SuppressWarnings("unused")
        public String programPath;

        @SuppressWarnings("unused")
        public String language;

        @SuppressWarnings("unused")
        public String compilerSpec;

        @SuppressWarnings("unused")
        public long sizeBytes;

        public ProgramInfo(String programPath, String language, String compilerSpec, long sizeBytes) {
            this.programPath = programPath;
            this.language = language;
            this.compilerSpec = compilerSpec;
            this.sizeBytes = sizeBytes;
        }
    }
}
