package reva.resources.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import reva.debug.DebugInfoCollector;
import reva.resources.AbstractResourceProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Resource provider for ReVa debug information.
 * Exposes comprehensive debug information as JSON including:
 * - System information (Java, OS)
 * - Ghidra information (version, extensions)
 * - ReVa configuration and status
 * - MCP server status and registered tools
 * - Open programs information
 * 
 * This is a read-only resource that provides the same information
 * as the capture-reva-debug-info tool, but as a JSON resource
 * instead of a zip file.
 */
public class RevaDebugInfoResource extends AbstractResourceProvider {
    private static final String RESOURCE_ID = "ghidra://reva-debug-info";
    private static final String RESOURCE_NAME = "reva-debug-info";
    private static final String RESOURCE_DESCRIPTION = "ReVa debug information including system info, Ghidra config, ReVa settings, MCP server status, and open programs";
    private static final String RESOURCE_MIME_TYPE = "application/json";
    private static final ObjectMapper JSON = new ObjectMapper();
    private final DebugInfoCollector debugCollector;

    public RevaDebugInfoResource(McpSyncServer server) {
        super(server);
        this.debugCollector = new DebugInfoCollector();
    }

    @Override
    public void register() {
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME,
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // No schema needed for simple resources
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                List<ResourceContents> resourceContents = new ArrayList<>();

                try {
                    // Collect all debug information
                    Map<String, Object> debugInfo = debugCollector.collectAll(null);
                    
                    // Convert to JSON string
                    String jsonContent = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(debugInfo);

                    TextResourceContents content = new TextResourceContents(
                        RESOURCE_ID,
                        RESOURCE_MIME_TYPE,
                        jsonContent
                    );
                    resourceContents.add(content);

                } catch (JsonProcessingException e) {
                    logError("Error serializing debug information to JSON", e);
                    ObjectNode errorResult = JSON.createObjectNode();
                    errorResult.put("error", "Error serializing debug information: " + e.getMessage());
                    try {
                        String errorJson = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                        TextResourceContents errorContent = new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            errorJson
                        );
                        resourceContents.add(errorContent);
                    } catch (JsonProcessingException e2) {
                        // Fallback to plain text error
                        TextResourceContents errorContent = new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            "{\"error\":\"Failed to serialize error message\"}"
                        );
                        resourceContents.add(errorContent);
                    }
                } catch (Exception e) {
                    logError("Error collecting debug information", e);
                    ObjectNode errorResult = JSON.createObjectNode();
                    errorResult.put("error", "Error collecting debug information: " + e.getMessage());
                    try {
                        String errorJson = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                        TextResourceContents errorContent = new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            errorJson
                        );
                        resourceContents.add(errorContent);
                    } catch (JsonProcessingException e2) {
                        TextResourceContents errorContent = new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            "{\"error\":\"Failed to serialize error message\"}"
                        );
                        resourceContents.add(errorContent);
                    }
                }

                return new ReadResourceResult(resourceContents);
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
    }
}
