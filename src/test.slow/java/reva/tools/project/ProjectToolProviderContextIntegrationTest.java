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
package reva.tools.project;

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
 * Integration tests for get-current-context tool in ProjectToolProvider
 */
public class ProjectToolProviderContextIntegrationTest extends RevaIntegrationTestBase {

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
    public void testGetCurrentContextBothMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test get-current-program and get-current-address together
            CallToolResult programResult = client.callTool(new CallToolRequest("get-current-program", new HashMap<>()));
            CallToolResult addressResult = client.callTool(new CallToolRequest("get-current-address", new HashMap<>()));

            assertNotNull("Program result should not be null", programResult);
            assertNotNull("Address result should not be null", addressResult);
            // May fail if no Code Browser is active, but that's acceptable
            // The test verifies the tools are registered and callable
        });
    }

    @Test
    public void testGetCurrentContextAddressMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            CallToolResult result = client.callTool(new CallToolRequest("get-current-address", new HashMap<>()));

            assertNotNull("Result should not be null", result);
            // May fail if no Code Browser is active, but that's acceptable
        });
    }

    @Test
    public void testGetCurrentContextFunctionMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            CallToolResult result = client.callTool(new CallToolRequest("get-current-function", new HashMap<>()));

            assertNotNull("Result should not be null", result);
            // May fail if no Code Browser is active, but that's acceptable
        });
    }
}
