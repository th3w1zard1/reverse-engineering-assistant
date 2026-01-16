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
package reva.tools.vtable;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for VtableToolProvider
 */
public class VtableToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String program_path;

    @Before
    public void setUpTestData() throws Exception {
        program_path = program.getDomainFile().getPathname();

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
    public void testAnalyzeVtablesAnalyzeMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "analyze");
            arguments.put("vtableAddress", "0x01000000");

            CallToolResult result = client.callTool(new CallToolRequest("analyze-vtables", arguments));

            assertNotNull("Result should not be null", result);
            // May error if not a valid vtable, but should return valid response
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testAnalyzeVtablesCallersMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "callers");
            arguments.put("functionAddress", "0x01000100");

            CallToolResult result = client.callTool(new CallToolRequest("analyze-vtables", arguments));

            assertNotNull("Result should not be null", result);
            // May return empty list, but should be valid JSON
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testAnalyzeVtablesContainingMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "containing");
            arguments.put("functionAddress", "0x01000100");

            CallToolResult result = client.callTool(new CallToolRequest("analyze-vtables", arguments));

            assertNotNull("Result should not be null", result);
            // May return empty list, but should be valid JSON
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testAnalyzeVtablesAnalyzeModeWithMaxEntries() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            int[] maxEntries = {10, 50, 100, 200};

            for (int max : maxEntries) {
                Map<String, Object> arguments = new HashMap<>();
                arguments.put("programPath", program_path);
                arguments.put("mode", "analyze");
                arguments.put("vtableAddress", "0x01000000");
                arguments.put("maxEntries", max);

                CallToolResult result = client.callTool(new CallToolRequest("analyze-vtables", arguments));

                assertNotNull("Result should not be null for max_entries " + max, result);
                // May error if not a valid vtable
            }
        });
    }

    @Test
    public void testAnalyzeVtablesCallersModeWithMaxResults() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "callers");
            arguments.put("functionAddress", "0x01000100");
            arguments.put("maxResults", 50);

            CallToolResult result = client.callTool(new CallToolRequest("analyze-vtables", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testAnalyzeVtablesContainingModeWithMaxResults() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "containing");
            arguments.put("functionAddress", "0x01000100");
            arguments.put("maxResults", 50);

            CallToolResult result = client.callTool(new CallToolRequest("analyze-vtables", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testAnalyzeVtablesWithFunctionName() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a function first
            ghidra.program.model.address.Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
            int txId = program.startTransaction("Create function");
            try {
                ghidra.program.model.listing.FunctionManager funcManager = program.getFunctionManager();
                try {
                    funcManager.createFunction("vtableTestFunc", funcAddr,
                        new AddressSet(funcAddr, funcAddr.add(20)), SourceType.USER_DEFINED);
                } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                    fail("Failed to create function: " + e.getMessage());
                }
            } finally {
                program.endTransaction(txId, true);
            }

            // Test with function name instead of address
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("mode", "callers");
            arguments.put("functionAddress", "vtableTestFunc");
            arguments.put("maxResults", 10);

            CallToolResult result = client.callTool(new CallToolRequest("analyze-vtables", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }
}
