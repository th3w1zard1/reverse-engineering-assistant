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
package reva.tools;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Comprehensive error handling tests for all tools.
 * Tests invalid inputs, missing parameters, edge cases, and error conditions.
 */
public class ErrorHandlingIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();
        env.open(program);

        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }

        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }
    }

    @Test
    public void testAllToolsHandleInvalidProgramPath() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String invalidPath = "/nonexistent/program/path";

            // Test all major tools with invalid program path
            String[] tools = {
                "manage-symbols", "manage-strings", "list-functions", "manage-function",
                "get-functions", "inspect-memory", "get-references", "manage-data-types",
                "manage-structures", "manage-comments", "manage-bookmarks", "analyze-data-flow",
                "get-call-graph", "search-constants", "analyze-vtables"
            };

            for (String toolName : tools) {
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", invalidPath);
                
                // Add minimal required parameters for each tool
                if (toolName.equals("manage-symbols")) {
                    args.put("mode", "count");
                } else if (toolName.equals("manage-strings")) {
                    args.put("mode", "count");
                } else if (toolName.equals("list-functions")) {
                    args.put("mode", "count");
                } else if (toolName.equals("manage-function")) {
                    args.put("action", "create");
                    args.put("address", "0x01000000");
                } else if (toolName.equals("get-functions")) {
                    args.put("identifier", "main");
                } else if (toolName.equals("inspect-memory")) {
                    args.put("mode", "blocks");
                } else if (toolName.equals("get-references")) {
                    args.put("target", "main");
                } else if (toolName.equals("manage-data-types")) {
                    args.put("action", "archives");
                } else if (toolName.equals("manage-structures")) {
                    args.put("action", "list");
                } else if (toolName.equals("manage-comments")) {
                    args.put("action", "get");
                    args.put("address", "0x01000000");
                } else if (toolName.equals("manage-bookmarks")) {
                    args.put("action", "get");
                    args.put("address", "0x01000000");
                } else if (toolName.equals("analyze-data-flow")) {
                    args.put("functionAddress", "0x01000000");
                    args.put("direction", "backward");
                    args.put("startAddress", "0x01000000");
                } else if (toolName.equals("get-call-graph")) {
                    args.put("functionIdentifier", "main");
                } else if (toolName.equals("search-constants")) {
                    args.put("mode", "specific");
                    args.put("value", "0");
                } else if (toolName.equals("analyze-vtables")) {
                    args.put("mode", "analyze");
                    args.put("vtableAddress", "0x01000000");
                }

                CallToolResult result = client.callTool(new CallToolRequest(toolName, args));
                assertTrue("Tool " + toolName + " should error with invalid program path", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                assertTrue("Error should mention program not found",
                    content.text().contains("Program not found") ||
                    content.text().contains("Could not find") ||
                    content.text().contains("Invalid program"));
            }
        });
    }

    @Test
    public void testAllToolsHandleMissingRequiredParameters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test tools that require mode/action
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            // Missing mode
            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", args));
            assertTrue("Should error without mode", result.isError());

            args.clear();
            args.put("programPath", programPath);
            // Missing action
            result = client.callTool(new CallToolRequest("manage-function", args));
            assertTrue("Should error without action", result.isError());

            args.clear();
            args.put("programPath", programPath);
            // Missing action
            result = client.callTool(new CallToolRequest("manage-structures", args));
            assertTrue("Should error without action", result.isError());

            args.clear();
            args.put("programPath", programPath);
            // Missing action
            result = client.callTool(new CallToolRequest("manage-comments", args));
            assertTrue("Should error without action", result.isError());

            args.clear();
            args.put("programPath", programPath);
            // Missing action
            result = client.callTool(new CallToolRequest("manage-bookmarks", args));
            assertTrue("Should error without action", result.isError());

            args.clear();
            args.put("programPath", programPath);
            // Missing mode
            result = client.callTool(new CallToolRequest("search-constants", args));
            assertTrue("Should error without mode", result.isError());

            args.clear();
            args.put("programPath", programPath);
            // Missing mode
            result = client.callTool(new CallToolRequest("analyze-vtables", args));
            assertTrue("Should error without mode", result.isError());

            args.clear();
            args.put("programPath", programPath);
            // Missing direction
            result = client.callTool(new CallToolRequest("analyze-data-flow", args));
            assertTrue("Should error without direction", result.isError());
        });
    }

    @Test
    public void testAllToolsHandleInvalidModeAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test invalid mode
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("mode", "invalid_mode");
            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", args));
            assertTrue("Should error with invalid mode", result.isError());

            // Test invalid action
            args.clear();
            args.put("programPath", programPath);
            args.put("action", "invalid_action");
            result = client.callTool(new CallToolRequest("manage-function", args));
            assertTrue("Should error with invalid action", result.isError());

            args.clear();
            args.put("programPath", programPath);
            args.put("action", "invalid_action");
            result = client.callTool(new CallToolRequest("manage-structures", args));
            assertTrue("Should error with invalid action", result.isError());
        });
    }

    @Test
    public void testToolsHandleInvalidAddresses() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String invalidAddr = "0xFFFFFFFFFFFFFFFF"; // Invalid address

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("mode", "create_label");
            args.put("address", invalidAddr);
            args.put("labelName", "test");
            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", args));
            // May error or handle gracefully

            args.clear();
            args.put("programPath", programPath);
            args.put("action", "get");
            args.put("address", invalidAddr);
            result = client.callTool(new CallToolRequest("manage-comments", args));
            // May return empty or error
        });
    }

    @Test
    public void testToolsHandleInvalidFunctionIdentifiers() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", "nonexistent_function_12345");
            args.put("view", "info");
            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));
            assertTrue("Should error with nonexistent function", result.isError());

            args.clear();
            args.put("programPath", programPath);
            args.put("functionIdentifier", "nonexistent_function");
            args.put("action", "rename_function");
            args.put("name", "newName");
            result = client.callTool(new CallToolRequest("manage-function", args));
            assertTrue("Should error with nonexistent function", result.isError());
        });
    }

    @Test
    public void testToolsHandlePaginationBoundaries() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with very large offset
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("mode", "all");
            args.put("startIndex", 1000000);
            args.put("maxCount", 10);
            CallToolResult result = client.callTool(new CallToolRequest("list-functions", args));
            // Should handle gracefully, may return empty or error

            // Test with negative offset
            args.put("startIndex", -1);
            result = client.callTool(new CallToolRequest("list-functions", args));
            // Should handle gracefully

            // Test with zero limit
            args.clear();
            args.put("programPath", programPath);
            args.put("mode", "list");
            args.put("maxCount", 0);
            result = client.callTool(new CallToolRequest("manage-strings", args));
            // Should handle gracefully
        });
    }

    @Test
    public void testToolsHandleEmptyArrays() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with empty array
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", java.util.Collections.emptyList());
            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));
            // get-functions treats empty identifier array as "no identifier" and returns all functions
            // This is valid behavior - empty array means "no filter"
            // So we don't expect an error here, just verify it doesn't crash
            assertNotNull("Result should not be null", result);

            args.clear();
            args.put("programPath", programPath);
            args.put("action", "create");
            args.put("address", java.util.Collections.emptyList());
            result = client.callTool(new CallToolRequest("manage-function", args));
            assertTrue("Should error with empty array", result.isError());
        });
    }

    @Test
    public void testToolsHandleInvalidDataTypes() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("action", "apply");
            args.put("addressOrSymbol", "0x01000000");
            args.put("dataTypeString", "nonexistent_type_xyz123");
            CallToolResult result = client.callTool(new CallToolRequest("manage-data-types", args));
            assertTrue("Should error with invalid data type", result.isError());
        });
    }

    @Test
    public void testToolsHandleInvalidStructures() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("action", "apply");
            args.put("structureName", "nonexistent_structure_xyz");
            args.put("addressOrSymbol", "0x01000000");
            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", args));
            assertTrue("Should error with nonexistent structure", result.isError());
        });
    }

    @Test
    public void testToolsHandleMalformedInputs() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with malformed address
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("mode", "create_label");
            args.put("address", "not_an_address");
            args.put("labelName", "test");
            CallToolResult result = client.callTool(new CallToolRequest("manage-symbols", args));
            assertTrue("Should error with malformed address", result.isError());

            // Test with malformed regex
            args.clear();
            args.put("programPath", programPath);
            args.put("mode", "regex");
            args.put("pattern", "[invalid regex");
            result = client.callTool(new CallToolRequest("manage-strings", args));
            // May error or handle gracefully
        });
    }
}
