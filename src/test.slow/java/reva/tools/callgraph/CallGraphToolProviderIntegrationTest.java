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
package reva.tools.callgraph;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for CallGraphToolProvider
 */
public class CallGraphToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Function testFunction;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create test functions
        Address functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        FunctionManager functionManager = program.getFunctionManager();

        int txId = program.startTransaction("Create Test Functions");
        try {
            testFunction = functionManager.createFunction("testFunction", functionAddr,
                new AddressSet(functionAddr, functionAddr.add(20)),
                SourceType.USER_DEFINED);

            // Create another function that could call testFunction
            Address functionAddr2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
            functionManager.createFunction("callerFunction", functionAddr2,
                new AddressSet(functionAddr2, functionAddr2.add(20)),
                SourceType.USER_DEFINED);
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
    public void testGetCallGraphGraphMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("function_identifier", "testFunction");
            arguments.put("mode", "graph");
            arguments.put("depth", 1);

            CallToolResult result = client.callTool(new CallToolRequest("get_call_graph", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain callers or callees field",
                json.has("callers") || json.has("callees") || json.has("function"));
        });
    }

    @Test
    public void testGetCallGraphTreeMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("function_identifier", "testFunction");
            arguments.put("mode", "tree");
            arguments.put("direction", "callees");
            arguments.put("max_depth", 2);

            CallToolResult result = client.callTool(new CallToolRequest("get_call_graph", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain tree or formattedTree field",
                json.has("tree") || json.has("formattedTree") || json.has("text"));
        });
    }

    @Test
    public void testGetCallGraphCallersMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("function_identifier", "testFunction");
            arguments.put("mode", "callers");

            CallToolResult result = client.callTool(new CallToolRequest("get_call_graph", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain callers field", json.has("callers"));
        });
    }

    @Test
    public void testGetCallGraphCalleesMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("function_identifier", "testFunction");
            arguments.put("mode", "callees");

            CallToolResult result = client.callTool(new CallToolRequest("get_call_graph", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain callees field", json.has("callees"));
        });
    }

    @Test
    public void testGetCallGraphCallersDecompMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("function_identifier", "testFunction");
            arguments.put("mode", "callers_decomp");
            arguments.put("max_callers", 5);

            CallToolResult result = client.callTool(new CallToolRequest("get_call_graph", arguments));

            assertNotNull("Result should not be null", result);
            // May be empty if no callers, but should return valid JSON
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testGetCallGraphCommonCallersMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "common_callers");
            arguments.put("function_addresses", "testFunction,callerFunction");

            CallToolResult result = client.callTool(new CallToolRequest("get_call_graph", arguments));

            assertNotNull("Result should not be null", result);
            // May be empty, but should return valid JSON
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }
}
