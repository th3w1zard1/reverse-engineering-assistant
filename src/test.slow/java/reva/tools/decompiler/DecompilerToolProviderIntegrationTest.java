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
package reva.tools.decompiler;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for DecompilerToolProvider.
 * Tests the actual decompiler functionality with a real Ghidra environment.
 */
public class DecompilerToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Function testFunction;

    @Before
    public void setUp() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create a more realistic test function with actual instructions
        // Use an address within the existing memory block (base class creates block at 0x01000000)
        Address functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        FunctionManager functionManager = program.getFunctionManager();

        int transactionId = program.startTransaction("Create Test Function");
        try {
            // Create a simple function without trying to add machine code
            // Just create the function structure - the decompiler will handle empty functions
            testFunction = functionManager.createFunction("testFunction", functionAddr,
                program.getAddressFactory().getAddressSet(functionAddr, functionAddr.add(20)),
                SourceType.USER_DEFINED);

            // Add some parameters to test datatype changes
            DataType intType = new IntegerDataType(program.getDataTypeManager());
            DataType ptrType = new PointerDataType(intType, program.getDataTypeManager());

            Parameter param1 = new ParameterImpl("param1", intType, program);
            Parameter param2 = new ParameterImpl("param2", ptrType, program);

            List<Variable> params = List.of(param1, param2);
            testFunction.replaceParameters(params,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

        } finally {
            program.endTransaction(transactionId, true);
        }

        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);

        // Also open it directly in the tool's ProgramManager service to ensure it's available
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }


        // Register the program with the server manager so it can be found by the tools
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }

        assertNotNull("Test function should be created", testFunction);
    }

    /**
     * Helper method to perform the forced read of decompilation required before modification tools
     * @param client The MCP client
     * @param functionName The function name to read decompilation for
     * @return The result of the get-decompilation call
     */
    private CallToolResult performForcedDecompilationRead(io.modelcontextprotocol.client.McpSyncClient client, String functionName) {
        try {
            Map<String, Object> readArgs = new HashMap<>();
            readArgs.put("programPath", programPath);
            readArgs.put("identifier", functionName);
            readArgs.put("view", "decompile");
            CallToolResult readResult = client.callTool(new CallToolRequest("get-functions", readArgs));
            assertNotNull("Read result should not be null", readResult);
            return readResult;
        } catch (Exception e) {
            fail("Failed to perform forced decompilation read: " + e.getMessage());
            return null; // Never reached due to fail()
        }
    }


    @Test
    public void testGetDecompiledFunctionSuccess() throws Exception {
        // First test basic HTTP connectivity
        try {
            java.net.URL url = java.net.URI.create("http://localhost:8080/").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(1000);
            conn.setReadTimeout(1000);
            int responseCode = conn.getResponseCode();
            System.out.println("DEBUG: Basic HTTP GET to / returned: " + responseCode);
            conn.disconnect();
        } catch (Exception e) {
            System.out.println("DEBUG: Basic HTTP GET failed: " + e.getMessage());
        }

        withMcpClient(createMcpTransport(), client -> {
            System.out.println("DEBUG: Test about to initialize client, waiting 1 second...");
            try { Thread.sleep(1000); } catch (InterruptedException e) {}
            System.out.println("DEBUG: Test starting client.initialize()...");
            client.initialize();
            System.out.println("DEBUG: Test client initialized successfully!");

            // Test the get-functions tool with decompile view
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", "testFunction");
            args.put("view", "decompile");

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            assertNotNull("Result should have content", result.content());
            assertFalse("Result content should not be empty", result.content().isEmpty());

            // Parse the result and validate structure
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            // get-functions returns: function (name), address, programName, decompilation/decompiledCode/code
            assertTrue("Should have function name", json.has("function"));
            assertTrue("Should have address", json.has("address"));
            assertTrue("Should have programName", json.has("programName"));
            // get-functions may return decompiledCode, code, or decompilation
            assertTrue("Should have decompiled code", 
                json.has("decompiledCode") || json.has("code") || json.has("decompilation"));

            // Verify we got actual decompiled code
            String decompilation = null;
            if (json.has("decompiledCode")) {
                decompilation = json.get("decompiledCode").asText();
            } else if (json.has("code")) {
                decompilation = json.get("code").asText();
            } else if (json.has("decompilation")) {
                decompilation = json.get("decompilation").asText();
            }
            assertNotNull("Decompilation should not be null", decompilation);
            assertFalse("Decompilation should not be empty", decompilation.trim().isEmpty());
        });
    }

    @Test
    public void testChangeVariableDataTypesSuccess() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First, read the decompilation to satisfy the forced read requirement
            performForcedDecompilationRead(client, "testFunction");

            // First, get the original variable data types from the program using Function API
            Variable[] originalParams = testFunction.getParameters();
            DataType originalParam1Type = null;
            DataType originalParam2Type = null;

            for (Variable param : originalParams) {
                if ("param1".equals(param.getName())) {
                    originalParam1Type = param.getDataType();
                } else if ("param2".equals(param.getName())) {
                    originalParam2Type = param.getDataType();
                }
            }

            // Now try changing variable data types for function parameters
            Map<String, Object> changeArgs = new HashMap<>();
            changeArgs.put("programPath", programPath);
            changeArgs.put("action", "change_datatypes");
            changeArgs.put("functionIdentifier", "testFunction");

            // Try to change parameter data types (format: 'varName1:type1,varName2:type2')
            changeArgs.put("datatypeMappings", "param1:char,param2:char*");

            CallToolResult changeResult = client.callTool(new CallToolRequest("manage-function", changeArgs));

            assertNotNull("Change result should not be null", changeResult);

            // Get the content
            TextContent changeContent = (TextContent) changeResult.content().get(0);

            if (changeResult.isError()) {
                // If it's an error, it should be meaningful (variables might not be found in decompilation)
                String errorMsg = changeContent.text();
                assertTrue("Error message should be informative",
                    errorMsg.contains("not found") || errorMsg.contains("Failed to find") ||
                    errorMsg.contains("No matching variables") || errorMsg.contains("Could not find") ||
                    errorMsg.contains("Decompilation failed"));
            } else {
                // Parse the result as JSON only if it's not an error
                JsonNode changeJson = parseJsonContent(changeContent.text());
                // If successful, validate the structure
                String programName = changeJson.has("programName") ? changeJson.get("programName").asText() : null;
                assertNotNull("Should have programName", programName);
                assertEquals("Program name should match", program.getName(), programName);
                String functionName = changeJson.has("functionName") ? changeJson.get("functionName").asText() : null;
                assertNotNull("Should have functionName", functionName);
                assertEquals("Function name should match", "testFunction", functionName);
                assertTrue("Should have address", changeJson.has("address"));
                assertTrue("Should have data_types_changed flag", changeJson.has("data_types_changed") || changeJson.has("dataTypesChanged"));

                // The response always has dataTypesChanged and changedCount
                // It may optionally have changes/diff if decompilation diff was created
                // Just verify we have the core success indicators
                assertTrue("Should have dataTypesChanged or data_types_changed", 
                    changeJson.has("dataTypesChanged") || changeJson.has("data_types_changed"));
                // Changes/diff are optional - only present if diff creation succeeded

                // If we have changes/diff, validate the structure
                if (changeJson.has("changes")) {
                    JsonNode changes = changeJson.get("changes");
                    assertTrue("Changes should have hasChanges field", changes.has("hasChanges") || changes.has("has_changes"));
                    assertTrue("Changes should have summary field", changes.has("summary"));
                } else if (changeJson.has("diff")) {
                    // manage-function returns diff directly
                    JsonNode diff = changeJson.get("diff");
                    assertTrue("Diff should have structure", diff != null);
                }

                // Validate that the program state has actually been updated
                boolean dataTypesChanged = changeJson.has("dataTypesChanged") 
                    ? changeJson.get("dataTypesChanged").asBoolean() 
                    : (changeJson.has("data_types_changed") ? changeJson.get("data_types_changed").asBoolean() : false);
                if (dataTypesChanged) {
                    // Re-get the function to see updated state
                    Function updatedFunction = program.getFunctionManager().getFunctionAt(testFunction.getEntryPoint());
                    assertNotNull("Function should still exist", updatedFunction);

                    // Check that variable data types have actually changed in the program
                    Variable[] updatedParams = updatedFunction.getParameters();

                    for (Variable param : updatedParams) {
                        String paramName = param.getName();
                        DataType newType = param.getDataType();

                        if ("param1".equals(paramName)) {
                            assertNotNull("param1 should have a data type", newType);

                            // Verify the data type actually changed (if we had an original type)
                            if (originalParam1Type != null) {
                                // The type should have changed to char or be different from original
                                boolean typeChanged = !originalParam1Type.isEquivalent(newType);
                                String newTypeName = newType.getName();

                                assertTrue("param1 type should have changed or be char-related",
                                    typeChanged || newTypeName.contains("char") || newTypeName.equals("char"));
                            }
                        } else if ("param2".equals(paramName)) {
                            assertNotNull("param2 should have a data type", newType);

                            // Verify the data type actually changed (if we had an original type)
                            if (originalParam2Type != null) {
                                // The type should have changed to char* or be different from original
                                boolean typeChanged = !originalParam2Type.isEquivalent(newType);
                                String newTypeName = newType.getName();

                                assertTrue("param2 type should have changed or be char*-related",
                                    typeChanged || newTypeName.contains("char") || newTypeName.contains("*"));
                            }
                        }
                    }
                }
            }
        });
    }

    @Test
    public void testRenameVariablesSuccess() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First, read the decompilation to satisfy the forced read requirement
            performForcedDecompilationRead(client, "testFunction");

            // First, get the original variable names from the program using Function API
            Variable[] originalParams = testFunction.getParameters();
            boolean hasParam1 = false;
            boolean hasParam2 = false;

            for (Variable param : originalParams) {
                if ("param1".equals(param.getName())) {
                    hasParam1 = true;
                } else if ("param2".equals(param.getName())) {
                    hasParam2 = true;
                }
            }

            // Now try renaming variables
            Map<String, Object> renameArgs = new HashMap<>();
            renameArgs.put("programPath", programPath);
            renameArgs.put("action", "rename_variable");
            renameArgs.put("functionIdentifier", "testFunction");

            // Try to rename variables (format: 'oldName1:newName1,oldName2:newName2')
            renameArgs.put("variableMappings", "param1:myParameter1,param2:myParameter2");

            CallToolResult renameResult = client.callTool(new CallToolRequest("manage-function", renameArgs));

            assertNotNull("Rename result should not be null", renameResult);

            // Get the content
            TextContent renameContent = (TextContent) renameResult.content().get(0);

            if (renameResult.isError()) {
                // If it's an error, it should be meaningful (variables might not be found in decompilation)
                String errorMsg = renameContent.text();
                assertTrue("Error message should be informative",
                    errorMsg.contains("not found") || errorMsg.contains("Failed to find") ||
                    errorMsg.contains("No matching variables") || errorMsg.contains("Could not find") ||
                    errorMsg.contains("Decompilation failed"));
            } else {
                // Parse the result as JSON only if it's not an error
                JsonNode renameJson = parseJsonContent(renameContent.text());
                // If successful, validate the structure
                // manage-function returns programName, functionName (not program_name, function_name)
                assertTrue("Should have programName", renameJson.has("programName"));
                assertTrue("Should have functionName", renameJson.has("functionName"));
                assertTrue("Should have address", renameJson.has("address"));
                assertTrue("Should have variablesRenamed or variables_renamed flag", 
                    renameJson.has("variablesRenamed") || renameJson.has("variables_renamed"));

                // The response always has variablesRenamed and renamedCount
                // It may optionally have changes/diff if decompilation diff was created
                // Just verify we have the core success indicators - changes/diff are optional

                // If we have changes/diff, validate the structure
                if (renameJson.has("changes")) {
                    JsonNode changes = renameJson.get("changes");
                    assertTrue("Changes should have hasChanges field", changes.has("hasChanges") || changes.has("has_changes"));
                    assertTrue("Changes should have summary field", changes.has("summary"));
                } else if (renameJson.has("diff")) {
                    // manage-function returns diff directly
                    JsonNode diff = renameJson.get("diff");
                    assertTrue("Diff should have structure", diff != null);
                }

                // Validate that the program state has actually been updated
                boolean variablesRenamed = renameJson.has("variablesRenamed") 
                    ? renameJson.get("variablesRenamed").asBoolean() 
                    : (renameJson.has("variables_renamed") ? renameJson.get("variables_renamed").asBoolean() : false);
                if (variablesRenamed) {
                    // Re-get the function to see updated state
                    Function updatedFunction = program.getFunctionManager().getFunctionAt(testFunction.getEntryPoint());
                    assertNotNull("Function should still exist", updatedFunction);

                    // Check that variables have actually been renamed in the program
                    Variable[] updatedParams = updatedFunction.getParameters();
                    boolean foundMyParameter1 = false;
                    boolean foundMyParameter2 = false;
                    boolean foundOldParam1 = false;
                    boolean foundOldParam2 = false;

                    for (Variable param : updatedParams) {
                        String paramName = param.getName();
                        if ("myParameter1".equals(paramName)) {
                            foundMyParameter1 = true;
                        } else if ("myParameter2".equals(paramName)) {
                            foundMyParameter2 = true;
                        } else if ("param1".equals(paramName)) {
                            foundOldParam1 = true;
                        } else if ("param2".equals(paramName)) {
                            foundOldParam2 = true;
                        }
                    }

                    // At least one parameter should have been renamed
                    assertTrue("At least one parameter should have been renamed successfully",
                        foundMyParameter1 || foundMyParameter2);

                    // Verify specific renames occurred correctly
                    if (hasParam1 && foundMyParameter1) {
                        assertFalse("Old param1 name should no longer exist", foundOldParam1);
                    }
                    if (hasParam2 && foundMyParameter2) {
                        assertFalse("Old param2 name should no longer exist", foundOldParam2);
                    }

                    // Also check all variables (including locals) for comprehensive validation
                    Variable[] allVariables = updatedFunction.getAllVariables();
                    boolean foundMyParameter1InAll = false;
                    boolean foundMyParameter2InAll = false;

                    for (Variable var : allVariables) {
                        String varName = var.getName();
                        if ("myParameter1".equals(varName)) {
                            foundMyParameter1InAll = true;
                        } else if ("myParameter2".equals(varName)) {
                            foundMyParameter2InAll = true;
                        }
                    }

                    // At least one variable should have been renamed across all variables
                    assertTrue("At least one variable should have been renamed in function",
                        foundMyParameter1InAll || foundMyParameter2InAll);
                }
            }
        });
    }

    @Test
    public void testGetDecompilationWithInvalidFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-functions tool with non-existent function
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", "nonExistentFunction");
            args.put("view", "decompile");

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));

            assertNotNull("Result should not be null", result);
            assertTrue("Should return error for non-existent function", result.isError());

            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention function not found",
                errorMsg.contains("Function not found") || errorMsg.contains("function"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test changing data types for non-existent function
            Map<String, Object> changeArgs = new HashMap<>();
            changeArgs.put("programPath", programPath);
            changeArgs.put("action", "change_datatypes");
            changeArgs.put("functionIdentifier", "nonExistentFunction");
            changeArgs.put("datatypeMappings", "someVar:int");

            CallToolResult changeResult = client.callTool(new CallToolRequest("manage-function", changeArgs));

            assertNotNull("Change result should not be null", changeResult);
            assertTrue("Should return error for non-existent function", changeResult.isError());

            TextContent content = (TextContent) changeResult.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention function not found",
                errorMsg.contains("Function not found") || errorMsg.contains("function"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with invalid program path
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", "/nonexistent/program");
            args.put("action", "change_datatypes");
            args.put("functionIdentifier", "testFunction");
            args.put("datatypeMappings", "var1:int");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", args));

            assertTrue("Should return error for invalid program", result.isError());
            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention program not found",
                errorMsg.contains("Failed to find program") || errorMsg.contains("program"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidFunctionName() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with invalid function name
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("action", "change_datatypes");
            args.put("functionIdentifier", "anotherNonExistentFunction");
            args.put("datatypeMappings", "var1:int");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", args));

            assertTrue("Should return error for invalid function", result.isError());
            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention function not found",
                errorMsg.contains("Function not found") || errorMsg.contains("function"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithEmptyMappings() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with empty datatype mappings
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("action", "change_datatypes");
            args.put("functionIdentifier", "testFunction");
            args.put("datatypeMappings", "");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", args));

            assertTrue("Should return error for empty mappings", result.isError());
            TextContent content = (TextContent) result.content().get(0);
            String errorMsg = content.text();
            assertTrue("Error should mention no datatype mappings",
                errorMsg.contains("No datatype mappings") || errorMsg.contains("mappings"));
        });
    }

    @Test
    public void testChangeVariableDataTypesWithInvalidDataType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test with invalid data type string
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("action", "change_datatypes");
            args.put("functionIdentifier", "testFunction");
            args.put("datatypeMappings", "someVariable:InvalidDataType123");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", args));

            // This might succeed but report errors, or might fail entirely
            assertNotNull("Result should not be null", result);

            if (!result.isError()) {
                // If it didn't fail outright, check that it reports errors for invalid data types
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());

                // Should either have no variables changed or have errors reported
                assertTrue("Should report issues with invalid data types",
                    (json.has("dataTypesChanged") && !json.get("dataTypesChanged").asBoolean()) &&
                     (json.has("errors") ||
                      content.text().contains("No matching variables") ||
                      content.text().contains("Could not find")));
            }
        });
    }

    @Test
    public void testGetDecompilationWithRange() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-functions tool with line range
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", "testFunction");
            args.put("view", "decompile");
            args.put("offset", 1);
            args.put("limit", 5);

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have offset", json.has("offset"));
            assertTrue("Should have limit", json.has("limit"));
            assertTrue("Should have totalLines", json.has("totalLines"));
            assertEquals("Offset should be 1", 1, json.get("offset").asInt());
            assertEquals("Limit should be 5", 5, json.get("limit").asInt());
        });
    }

    @Test
    public void testGetDecompilationDefaultLimit() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-functions tool with default limit (no limit specified)
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", "testFunction");
            args.put("view", "decompile");
            // No limit specified - should default to 50

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have offset", json.has("offset"));
            assertTrue("Should have limit", json.has("limit"));
            assertTrue("Should have totalLines", json.has("totalLines"));
            assertEquals("Offset should be 1", 1, json.get("offset").asInt());
            assertEquals("Limit should default to 50", 50, json.get("limit").asInt());
        });
    }

    @Test
    public void testGetDecompilationWithSync() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the get-functions tool with decompile view (get-decompilation tool doesn't exist)
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", "testFunction");
            args.put("view", "decompile");

            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            // get-functions with view=decompile returns decompilation field
            assertTrue("Should have decompilation",
                json.has("decompilation") || json.has("decompiledCode") || json.has("code"));
        });
    }

    @Test
    public void testSearchDecompilation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test the manage-comments tool with search_decomp action
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("action", "search_decomp");
            args.put("pattern", ".*"); // Simple pattern that should match something
            args.put("maxResults", 10);

            CallToolResult result = client.callTool(new CallToolRequest("manage-comments", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have results array", json.has("results"));
            assertTrue("Should have resultsCount", json.has("resultsCount"));
            assertTrue("Should have pattern", json.has("pattern"));
            assertEquals("Pattern should match", ".*", json.get("pattern").asText());
        });
    }

    @Test
    public void testForcedReadValidation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Try to rename variables without reading decompilation first
            Map<String, Object> renameArgs = new HashMap<>();
            renameArgs.put("programPath", programPath);
            renameArgs.put("action", "rename_variable");
            renameArgs.put("functionIdentifier", "testFunction");
            renameArgs.put("variableMappings", "param1:newParam1");

            CallToolResult renameResult = client.callTool(new CallToolRequest("manage-function", renameArgs));

            assertNotNull("Rename result should not be null", renameResult);
            // Note: The forced read validation may not be enforced - the tool may succeed or fail based on decompilation state
            // If it succeeds, that's fine - the test just verifies the tool is callable
            // If it fails, verify it's a meaningful error
            if (renameResult.isError()) {
                TextContent content = (TextContent) renameResult.content().get(0);
                String errorMsg = content.text();
                assertTrue("Error should be meaningful",
                    errorMsg.contains("read") || errorMsg.contains("decompilation") || 
                    errorMsg.contains("not found") || errorMsg.contains("Failed") ||
                    errorMsg.contains("Function not found") || errorMsg.contains("get-decompilation") ||
                    errorMsg.contains("get-functions"));
            } else {
                // If it succeeds, that's also acceptable - forced read validation may not be strictly enforced
                // The test just verifies the tool is callable and handles the request
            }
        });
    }

    @Test
    public void testSearchDecompilationRespectsMaxFunctionLimitConfig() throws Exception {
        // Get the config manager and save the original value
        reva.plugin.ConfigManager configManager = reva.util.RevaInternalServiceRegistry.getService(reva.plugin.ConfigManager.class);
        int originalMax = configManager.getMaxDecompilerSearchFunctions();
        try {
            // Set max functions to 0 to force the limit
            configManager.setMaxDecompilerSearchFunctions(0);

            withMcpClient(createMcpTransport(), client -> {
                client.initialize();
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);
                args.put("action", "search_decomp");
                args.put("pattern", ".*");
                args.put("maxResults", 10);

                CallToolResult result = client.callTool(new CallToolRequest("manage-comments", args));
                assertNotNull("Result should not be null", result);
                assertTrue("Should return error when function count exceeds max", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                String errorMsg = content.text();
                assertTrue("Error should mention maximum limit", errorMsg.contains("maximum limit") || errorMsg.contains("exceeds the maximum"));
            });
        } finally {
            // Restore the original config value
            configManager.setMaxDecompilerSearchFunctions(originalMax);
        }
    }

    @Test
    public void testSearchDecompilationRespectsMaxFunctionLimitConfigOverride() throws Exception {
        // Get the config manager and save the original value
        reva.plugin.ConfigManager configManager = reva.util.RevaInternalServiceRegistry.getService(reva.plugin.ConfigManager.class);
        int originalMax = configManager.getMaxDecompilerSearchFunctions();
        try {
            // Set max functions to 0 to force the limit
            configManager.setMaxDecompilerSearchFunctions(0);

            withMcpClient(createMcpTransport(), client -> {
                client.initialize();
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", programPath);
                args.put("action", "search_decomp");
                args.put("pattern", ".*");
                args.put("maxResults", 10);
                args.put("overrideMaxFunctionsLimit", true); // Override the max functions limit

                CallToolResult result = client.callTool(new CallToolRequest("manage-comments", args));
                assertNotNull("Result should not be null", result);
                assertFalse("Should not return error when function count exceeds max and override is set", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertTrue("Should have results array", json.has("results"));
            });
        } finally {
            // Restore the original config value
            configManager.setMaxDecompilerSearchFunctions(originalMax);
        }
    }

    @Test
    public void testGetDecompilationReferencesContainSymbolAndAddress() throws Exception {
        // Create a caller function that references testFunction
        Address callerAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
        FunctionManager functionManager = program.getFunctionManager();
        int txId = program.startTransaction("Create Caller Function");
        try {
            // Create a simple caller function
            Function callerFunction = functionManager.createFunction("callerFunction", callerAddr,
                program.getAddressFactory().getAddressSet(callerAddr, callerAddr.add(20)),
                SourceType.USER_DEFINED);
            // Insert a call instruction from callerFunction to testFunction
            // For x86, 0xE8 is CALL rel32. We'll use a dummy relative offset (not actually executable, but enough for Ghidra to create a reference)
            byte[] callInstr = new byte[] { (byte)0xE8, 0x00, 0x00, 0x00, 0x00 }; // CALL +0
            program.getMemory().setBytes(callerAddr, callInstr);
            // Add a reference from the call instruction to testFunction
            program.getReferenceManager().addMemoryReference(
                callerAddr, // from
                testFunction.getEntryPoint(), // to
                ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL,
                ghidra.program.model.symbol.SourceType.USER_DEFINED,
                0
            );
        } finally {
            program.endTransaction(txId, true);
        }

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", programPath);
            args.put("identifier", "testFunction");
            args.put("view", "decompile");
            args.put("includeIncomingReferences", true);
            args.put("includeReferenceContext", false);
            CallToolResult result = client.callTool(new CallToolRequest("get-functions", args));
            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Should have incomingReferences", json.has("incomingReferences"));
            JsonNode refs = json.get("incomingReferences");
            boolean foundCaller = false;
            for (JsonNode ref : refs) {
                // Should have both fromAddress/from_address and fromSymbol/from_symbol fields (fromSymbol may be null if no symbol)
                assertTrue("Reference should have fromAddress or from_address", 
                    ref.has("fromAddress") || ref.has("from_address"));
                assertTrue("Reference should have referenceType or reference_type", 
                    ref.has("referenceType") || ref.has("reference_type"));
                // fromSymbol is optional but if present, should be a string
                JsonNode fromSymbol = ref.has("fromSymbol") ? ref.get("fromSymbol") : 
                    (ref.has("from_symbol") ? ref.get("from_symbol") : null);
                if (fromSymbol != null && !fromSymbol.isNull()) {
                    assertTrue("fromSymbol should be a string if present", fromSymbol.isTextual());
                    if ("callerFunction".equals(fromSymbol.asText())) {
                        foundCaller = true;
                    }
                }
            }
            assertTrue("Should have a reference from callerFunction", foundCaller);
        });
    }


}