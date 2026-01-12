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
package reva.tools.symbols;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for SymbolToolProvider
 */
public class SymbolToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Address testAddress;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create test data and label
        testAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        int txId = program.startTransaction("Setup test data");
        try {
            Listing listing = program.getListing();
            listing.createData(testAddress, new ByteDataType(), 1);
            SymbolTable symbolTable = program.getSymbolTable();
            symbolTable.createLabel(testAddress, "testLabel",
                program.getGlobalNamespace(),
                ghidra.program.model.symbol.SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(txId, true);
        }

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
    public void testManageSymbolsCountMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "count");

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain count field", json.has("count"));
            assertTrue("Count should be non-negative", json.get("count").asInt() >= 0);
        });
    }

    @Test
    public void testManageSymbolsSymbolsMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "symbols");
            arguments.put("max_count", 10);

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain symbols field", json.has("symbols"));
        });
    }

    @Test
    public void testManageSymbolsCreateLabelMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "create_label");
            arguments.put("address", "0x01000200");
            arguments.put("label_name", "newTestLabel");

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
        });
    }

    @Test
    public void testManageSymbolsRenameDataMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "rename_data");
            arguments.put("address", "0x01000100");
            arguments.put("new_name", "renamedLabel");

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            // Should succeed or fail gracefully
        });
    }

    @Test
    public void testManageSymbolsImportsMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "imports");

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain imports field", json.has("imports") || json.has("groupedByLibrary"));
        });
    }

    @Test
    public void testManageSymbolsExportsMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "exports");

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain exports field", json.has("exports"));
        });
    }

    @Test
    public void testManageSymbolsClassesMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "classes");

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain classes field", json.has("classes"));
        });
    }

    @Test
    public void testManageSymbolsNamespacesMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "namespaces");

            CallToolResult result = client.callTool(new CallToolRequest("manage_symbols", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain namespaces field", json.has("namespaces"));
        });
    }
}
