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
            try {
                testFunction = functionManager.createFunction("testFunction", functionAddr,
                    new AddressSet(functionAddr, functionAddr.add(20)),
                    SourceType.USER_DEFINED);
            } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                fail("Failed to create testFunction: " + e.getMessage());
            }
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

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

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

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

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

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

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

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

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

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("testFunction", json.get("name").asText());
        });
    }

    @Test
    public void testGetFunctionsBatchOperations() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create additional function
            Address funcAddr2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
            int txId = program.startTransaction("Create second function");
            try {
                FunctionManager funcManager = program.getFunctionManager();
                try {
                    funcManager.createFunction("testFunction2", funcAddr2,
                        new AddressSet(funcAddr2, funcAddr2.add(20)), SourceType.USER_DEFINED);
                } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                    fail("Failed to create testFunction2: " + e.getMessage());
                }
            } finally {
                program.endTransaction(txId, true);
            }

            // Test batch get with array of identifiers
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", java.util.Arrays.asList("testFunction", "testFunction2"));
            arguments.put("view", "info");

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            // Batch operations return "results" not "functions"
            assertTrue("Result should contain results or functions array", 
                json.has("results") || json.has("functions"));
            JsonNode results = json.has("results") ? json.get("results") : json.get("functions");
            assertTrue("Should have at least 2 results", results.size() >= 2);
        });
    }

    @Test
    public void testGetFunctionsAllFunctions() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test getting all functions (identifier omitted)
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            // identifier omitted to get all functions
            arguments.put("view", "info");

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions array", json.has("functions"));
            JsonNode functions = json.get("functions");
            assertTrue("Should have at least testFunction", functions.size() >= 1);
        });
    }

    @Test
    public void testGetFunctionsDecompileViewWithAllOptions() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "testFunction");
            arguments.put("view", "decompile");
            arguments.put("offset", 1);
            arguments.put("limit", 10);
            arguments.put("includeCallers", true);
            arguments.put("includeCallees", true);
            arguments.put("includeComments", true);
            arguments.put("includeIncomingReferences", true);
            arguments.put("includeReferenceContext", true);

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain decompiledCode or code field",
                json.has("decompiledCode") || json.has("code"));
        });
    }

    @Test
    public void testGetFunctionsPagination() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test decompile view with pagination
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "testFunction");
            arguments.put("view", "decompile");
            arguments.put("offset", 1);
            arguments.put("limit", 5);

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertNotNull("Result should have valid JSON structure", json);
        });
    }

    @Test
    public void testGetFunctionsValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("identifier", "testFunction");
            arguments.put("view", "info");

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            // Verify function info matches actual program state
            FunctionManager funcManager = program.getFunctionManager();
            Function actualFunc = funcManager.getFunctionAt(testFunction.getEntryPoint());
            assertNotNull("Function should exist in program", actualFunc);
            assertEquals("Function name should match", "testFunction", actualFunc.getName());
            assertEquals("Function name in result should match", "testFunction", json.get("name").asText());
        });
    }
}
