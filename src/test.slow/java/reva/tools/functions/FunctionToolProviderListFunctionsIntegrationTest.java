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
package reva.tools.functions;

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
 * Integration tests for list-functions tool in FunctionToolProvider
 */
public class FunctionToolProviderListFunctionsIntegrationTest extends RevaIntegrationTestBase {

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

            // Create another function for testing
            Address functionAddr2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
            functionManager.createFunction("mainFunction", functionAddr2,
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
    public void testListFunctionsAllMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "all");
            arguments.put("maxCount", 10);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
        });
    }

    @Test
    public void testListFunctionsCountMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "count");

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain count field", json.has("count"));
            assertTrue("Count should be at least 2", json.get("count").asInt() >= 2);
        });
    }

    @Test
    public void testListFunctionsSearchMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "search");
            arguments.put("query", "test");

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
        });
    }

    @Test
    public void testListFunctionsSimilarityMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "similarity");
            arguments.put("searchString", "testFunction");

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain matches field", json.has("matches"));
        });
    }

    @Test
    public void testListFunctionsUndefinedMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "undefined");
            arguments.put("minReferenceCount", 1);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain candidates field", json.has("candidates"));
        });
    }

    @Test
    public void testListFunctionsByIdentifiersMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "by_identifiers");
            arguments.put("identifiers", java.util.Arrays.asList("testFunction", "mainFunction"));

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
            JsonNode functions = json.get("functions");
            assertTrue("Should have at least 2 functions", functions.size() >= 2);
        });
    }

    @Test
    public void testListFunctionsFilterByTag() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First add a tag to testFunction
            Map<String, Object> tagArgs = new HashMap<>();
            tagArgs.put("programPath", programPath);
            tagArgs.put("mode", "add");
            tagArgs.put("function", "testFunction");
            tagArgs.put("tags", java.util.Arrays.asList("test_tag"));
            client.callTool(new CallToolRequest("manage-function-tags", tagArgs));

            // Now filter by tag
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "all");
            arguments.put("filterByTag", "test_tag");

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
        });
    }

    @Test
    public void testListFunctionsVerboseMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "all");
            arguments.put("verbose", true);
            arguments.put("maxCount", 10);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
            JsonNode functions = json.get("functions");
            if (functions.size() > 0) {
                JsonNode firstFunc = functions.get(0);
                // Verbose mode should include more details
                assertTrue("Verbose mode should have detailed fields", firstFunc.has("address") || firstFunc.has("entryPoint"));
            }
        });
    }

    @Test
    public void testListFunctionsUntaggedMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "all");
            arguments.put("untagged", true);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
        });
    }

    @Test
    public void testListFunctionsHasTagsMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First add a tag
            Map<String, Object> tagArgs = new HashMap<>();
            tagArgs.put("programPath", programPath);
            tagArgs.put("mode", "add");
            tagArgs.put("function", "testFunction");
            tagArgs.put("tags", java.util.Arrays.asList("has_tag_test"));
            client.callTool(new CallToolRequest("manage-function-tags", tagArgs));

            // Now filter by hasTags
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "all");
            arguments.put("hasTags", true);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
        });
    }

    @Test
    public void testListFunctionsValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "all");
            arguments.put("maxCount", 100);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            JsonNode functions = json.get("functions");

            // Verify functions match actual program state
            FunctionManager funcManager = program.getFunctionManager();
            int actualFuncCount = funcManager.getFunctionCount();
            assertTrue("Function count should match", functions.size() <= actualFuncCount);

            // Verify testFunction is in the list
            boolean foundTestFunction = false;
            for (JsonNode func : functions) {
                if ("testFunction".equals(func.get("name").asText())) {
                    foundTestFunction = true;
                    // Verify address matches
                    String addrStr = func.get("address").asText();
                    try {
                        Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addrStr);
                        Function actualFunc = funcManager.getFunctionAt(funcAddr);
                        assertNotNull("Function should exist at address", actualFunc);
                        assertEquals("Function name should match", "testFunction", actualFunc.getName());
                    } catch (ghidra.program.model.address.AddressFormatException e) {
                        fail("Invalid address format: " + addrStr + ": " + e.getMessage());
                    }
                    break;
                }
            }
            assertTrue("Should find testFunction in results", foundTestFunction);
        });
    }

    @Test
    public void testListFunctionsVerboseModeWithSearch() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "search");
            arguments.put("query", "test");
            arguments.put("verbose", true);
            arguments.put("maxCount", 10);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
            assertTrue("Result should indicate verbose mode", json.has("verbose") && json.get("verbose").asBoolean());
            JsonNode functions = json.get("functions");
            if (functions.size() > 0) {
                JsonNode firstFunc = functions.get(0);
                // Verbose mode should include more details
                assertTrue("Verbose mode should have detailed fields", 
                    firstFunc.has("address") || firstFunc.has("entryPoint") || firstFunc.has("name"));
            }
        });
    }

    @Test
    public void testListFunctionsVerboseModeWithSimilarity() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "similarity");
            arguments.put("searchString", "test");
            arguments.put("verbose", true);
            arguments.put("maxCount", 10);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
            assertTrue("Result should indicate verbose mode", json.has("verbose") && json.get("verbose").asBoolean());
            JsonNode functions = json.get("functions");
            if (functions.size() > 0) {
                JsonNode firstFunc = functions.get(0);
                // Verbose mode should include similarity and detailed fields
                assertTrue("Verbose mode should have detailed fields", 
                    firstFunc.has("address") || firstFunc.has("entryPoint") || firstFunc.has("name"));
            }
        });
    }

    @Test
    public void testListFunctionsVerboseModeWithByIdentifiers() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "by_identifiers");
            arguments.put("identifiers", java.util.Arrays.asList("testFunction", "mainFunction"));
            arguments.put("verbose", true);

            CallToolResult result = client.callTool(new CallToolRequest("list-functions", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain functions field", json.has("functions"));
            assertTrue("Result should indicate verbose mode", json.has("verbose") && json.get("verbose").asBoolean());
            JsonNode functions = json.get("functions");
            assertTrue("Should have at least one function", functions.size() > 0);
            JsonNode firstFunc = functions.get(0);
            // Verbose mode should include detailed fields
            assertTrue("Verbose mode should have detailed fields", 
                firstFunc.has("address") || firstFunc.has("entryPoint") || firstFunc.has("name"));
        });
    }
}
