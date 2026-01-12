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
package reva.tools.getfunction;

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
 * Integration tests for GetFunctionToolProvider
 */
public class GetFunctionToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Function testFunction;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create a test function
        Address functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        FunctionManager functionManager = program.getFunctionManager();

        int txId = program.startTransaction("Create Test Function");
        try {
            testFunction = functionManager.createFunction("testFunction", functionAddr,
                new AddressSet(functionAddr, functionAddr.add(20)),
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
    public void testGetFunctionDecompileView() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "testFunction");
            arguments.put("view", "decompile");

            CallToolResult result = client.callTool(new CallToolRequest("get-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            assertNotNull("Result content should not be null", result.content());
            assertFalse("Result content should not be empty", result.content().isEmpty());

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Result should contain decompiledCode or code field",
                json.has("decompiledCode") || json.has("code"));
        });
    }

    @Test
    public void testGetFunctionInfoView() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "testFunction");
            arguments.put("view", "info");

            CallToolResult result = client.callTool(new CallToolRequest("get-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Result should contain name field", json.has("name"));
            assertEquals("testFunction", json.get("name").asText());
            assertTrue("Result should contain address field", json.has("address"));
        });
    }

    @Test
    public void testGetFunctionDisassembleView() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "testFunction");
            arguments.put("view", "disassemble");

            CallToolResult result = client.callTool(new CallToolRequest("get-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Result should contain instructions field", json.has("instructions"));
        });
    }

    @Test
    public void testGetFunctionCallsView() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "testFunction");
            arguments.put("view", "calls");

            CallToolResult result = client.callTool(new CallToolRequest("get-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Result should contain calls field", json.has("calls"));
        });
    }

    @Test
    public void testGetFunctionByAddress() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "0x01000100");
            arguments.put("view", "info");

            CallToolResult result = client.callTool(new CallToolRequest("get-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("testFunction", json.get("name").asText());
        });
    }
}
