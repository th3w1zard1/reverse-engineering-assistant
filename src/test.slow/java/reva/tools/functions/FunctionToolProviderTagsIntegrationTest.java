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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
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
 * Integration tests for manage-function-tags tool in FunctionToolProvider
 */
public class FunctionToolProviderTagsIntegrationTest extends RevaIntegrationTestBase {

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
    public void testManageFunctionTagsGetMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("function", "testFunction");
            arguments.put("mode", "get");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function-tags", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain tags field", json.has("tags"));
            assertEquals("testFunction", json.get("function").asText());
        });
    }

    @Test
    public void testManageFunctionTagsSetMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("function", "testFunction");
            arguments.put("mode", "set");
            arguments.put("tags", Arrays.asList("tag1", "tag2"));

            CallToolResult result = client.callTool(new CallToolRequest("manage-function-tags", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain tags field", json.has("tags"));
            assertEquals(2, json.get("tags").size());
        });
    }

    @Test
    public void testManageFunctionTagsAddMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First set some tags
            Map<String, Object> setArgs = new HashMap<>();
            setArgs.put("programPath", programPath);
            setArgs.put("function", "testFunction");
            setArgs.put("mode", "set");
            setArgs.put("tags", Arrays.asList("tag1"));
            client.callTool(new CallToolRequest("manage-function-tags", setArgs));

            // Then add more
            Map<String, Object> addArgs = new HashMap<>();
            addArgs.put("programPath", programPath);
            addArgs.put("function", "testFunction");
            addArgs.put("mode", "add");
            addArgs.put("tags", Arrays.asList("tag2", "tag3"));

            CallToolResult result = client.callTool(new CallToolRequest("manage-function-tags", addArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain tags field", json.has("tags"));
            assertTrue("Should have at least 2 tags", json.get("tags").size() >= 2);
        });
    }

    @Test
    public void testManageFunctionTagsRemoveMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First set some tags
            Map<String, Object> setArgs = new HashMap<>();
            setArgs.put("programPath", programPath);
            setArgs.put("function", "testFunction");
            setArgs.put("mode", "set");
            setArgs.put("tags", Arrays.asList("tag1", "tag2", "tag3"));
            client.callTool(new CallToolRequest("manage-function-tags", setArgs));

            // Then remove one
            Map<String, Object> removeArgs = new HashMap<>();
            removeArgs.put("programPath", programPath);
            removeArgs.put("function", "testFunction");
            removeArgs.put("mode", "remove");
            removeArgs.put("tags", Arrays.asList("tag2"));

            CallToolResult result = client.callTool(new CallToolRequest("manage-function-tags", removeArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain tags field", json.has("tags"));
        });
    }

    @Test
    public void testManageFunctionTagsListMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("mode", "list");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function-tags", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain tags field", json.has("tags"));
            assertTrue("Result should contain totalTags field", json.has("totalTags"));
        });
    }
}
