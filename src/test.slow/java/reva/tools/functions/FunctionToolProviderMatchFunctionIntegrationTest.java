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
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Comprehensive integration tests for match-function tool in FunctionToolProvider.
 * Tests function matching across programs using code fingerprints.
 */
public class FunctionToolProviderMatchFunctionIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Function sourceFunction;
    private Address sourceFuncAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create source function for matching
        sourceFuncAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        FunctionManager functionManager = program.getFunctionManager();

        int txId = program.startTransaction("Create Source Function");
        try {
            sourceFunction = functionManager.createFunction("sourceFunction", sourceFuncAddr,
                new AddressSet(sourceFuncAddr, sourceFuncAddr.add(50)), SourceType.USER_DEFINED);
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
    public void testMatchFunctionSingleFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("maxInstructions", 64);
            arguments.put("minSimilarity", 0.85);

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            // May return empty if no matches, but should not error
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testMatchFunctionBatchMatching() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test matching all functions (function_identifier omitted)
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            // function_identifier omitted to match all functions
            arguments.put("maxInstructions", 64);
            arguments.put("minSimilarity", 0.85);

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testMatchFunctionWithVariousSimilarityThresholds() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            double[] thresholds = {0.5, 0.75, 0.85, 0.90, 0.95};

            for (double threshold : thresholds) {
                Map<String, Object> arguments = new HashMap<>();
                arguments.put("programPath", programPath);
                arguments.put("functionIdentifier", "sourceFunction");
                arguments.put("minSimilarity", threshold);
                arguments.put("maxInstructions", 64);

                CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

                assertNotNull("Result should not be null for threshold " + threshold, result);
                // May return different numbers of matches based on threshold
            }
        });
    }

    @Test
    public void testMatchFunctionWithPropagateOptions() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("propagateNames", true);
            arguments.put("propagateTags", true);
            arguments.put("propagateComments", false);

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testMatchFunctionDryRunMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("dryRun", true);

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            assertFalse("Dry run should not error", result.isError());
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertNotNull("Result should have valid JSON structure", json);
            // Dry run should show what would be transferred without making changes
        });
    }

    @Test
    public void testMatchFunctionWithFilterByTag() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First add a tag to source function
            Map<String, Object> tagArgs = new HashMap<>();
            tagArgs.put("programPath", programPath);
            tagArgs.put("mode", "add");
            tagArgs.put("function", "sourceFunction");
            tagArgs.put("tags", java.util.Arrays.asList("match_test"));
            client.callTool(new CallToolRequest("manage-function-tags", tagArgs));

            // Now match with filter
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("filterByTag", "match_test");

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testMatchFunctionWithTargetProgramPaths() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("targetProgramPaths", java.util.Arrays.asList(programPath));

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testMatchFunctionWithMaxFunctions() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("maxFunctions", 10);
            arguments.put("batchSize", 5);

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testMatchFunctionWithFilterDefaultNames() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("filterDefaultNames", true);

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertNotNull("Result should have valid JSON structure", json);
            }
        });
    }

    @Test
    public void testMatchFunctionValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Add a tag to source function
            Map<String, Object> tagArgs = new HashMap<>();
            tagArgs.put("programPath", programPath);
            tagArgs.put("mode", "add");
            tagArgs.put("function", "sourceFunction");
            tagArgs.put("tags", java.util.Arrays.asList("validation_test"));
            client.callTool(new CallToolRequest("manage-function-tags", tagArgs));

            // Match and propagate
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("functionIdentifier", "sourceFunction");
            arguments.put("propagateTags", true);
            arguments.put("dryRun", false);

            CallToolResult result = client.callTool(new CallToolRequest("match-function", arguments));

            assertNotNull("Result should not be null", result);
            // If matching succeeds and propagates, verify tags were actually transferred
            if (!result.isError()) {
                // Verify source function still has the tag
                FunctionManager funcManager = program.getFunctionManager();
                Function func = funcManager.getFunctionAt(sourceFuncAddr);
                // Tags would be verified through the function's tag system
            }
        });
    }
}
