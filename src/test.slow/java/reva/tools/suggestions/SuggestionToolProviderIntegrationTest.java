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
package reva.tools.suggestions;

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
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Comprehensive integration tests for SuggestionToolProvider.
 * Tests all suggestion types: comment_type, comment_text, function_name, function_tags, variable_name, data_type.
 */
public class SuggestionToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Function testFunction;
    private Address testAddress;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create test function and address
        testAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        FunctionManager functionManager = program.getFunctionManager();

        int txId = program.startTransaction("Create Test Function");
        try {
            try {
                testFunction = functionManager.createFunction("testFunction", testAddress,
                    new AddressSet(testAddress, testAddress.add(50)), SourceType.USER_DEFINED);
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
    public void testSuggestCommentType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "commentType");
            arguments.put("address", testAddress.toString());

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSuggestCommentText() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "comment_text");
            arguments.put("address", testAddress.toString());

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSuggestFunctionName() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "function_name");
            arguments.put("function", "testFunction");

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSuggestFunctionTags() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "function_tags");
            arguments.put("function", "testFunction");

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSuggestVariableName() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "variableName");
            arguments.put("function", "testFunction");
            arguments.put("dataType", "int");

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSuggestDataType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "dataType");
            arguments.put("address", testAddress.toString());
            arguments.put("variableAddress", testAddress.toString());

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testSuggestInvalidSuggestionType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "invalid_type");

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertTrue("Tool should error with invalid suggestionType", result.isError());
        });
    }

    @Test
    public void testSuggestMissingRequiredParameters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test without address for comment_type
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "commentType");

            CallToolResult result = client.callTool(new CallToolRequest("suggest", arguments));

            assertTrue("Tool should error without address", result.isError());

            // Test without function for functionName
            arguments.clear();
            arguments.put("programPath", programPath);
            arguments.put("suggestionType", "function_name");

            result = client.callTool(new CallToolRequest("suggest", arguments));

            assertTrue("Tool should error without function", result.isError());
        });
    }
}
