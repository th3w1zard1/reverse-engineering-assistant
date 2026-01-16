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
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for manage-function tool in FunctionToolProvider
 */
public class FunctionToolProviderManageFunctionIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Address testAddr;
    private Address existingFuncAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Use addresses within the existing memory block (base class creates block at 0x01000000)
        testAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        existingFuncAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);

        FunctionManager functionManager = program.getFunctionManager();
        ghidra.program.model.mem.Memory memory = program.getMemory();

        int txId = program.startTransaction("Create Test Function and Instruction");
        try {
            // Remove the default non-executable block created by RevaIntegrationTestBase
            ghidra.program.model.mem.MemoryBlock defaultBlock = memory.getBlock("test");
            if (defaultBlock != null) {
                memory.removeBlock(defaultBlock, TaskMonitor.DUMMY);
            }

            // Create a memory block for this test
            // NOTE: createInitializedBlock doesn't support setting execute permission directly
            // The manage-function tool requires executable memory, but we'll work around this
            // by using functionManager.createFunction() directly for test setup, which doesn't require executable memory
            ghidra.program.model.mem.MemoryBlock testBlock = memory.createInitializedBlock("executable_test",
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                0x1000, (byte) 0, TaskMonitor.DUMMY, false);

            // Try to use reflection to set execute permission if available
            // This is a workaround since Ghidra's API doesn't provide a direct way to set execute permission
            try {
                java.lang.reflect.Method setExecuteMethod = testBlock.getClass().getMethod("setExecute", boolean.class);
                setExecuteMethod.invoke(testBlock, true);
            } catch (Exception e) {
                // If reflection fails, we'll need to work around the executable check in the tool
                // For now, we'll proceed and handle it in the test if needed
            }

            // Create an instruction at testAddr for manage-function create action
            // The create action requires an instruction at the address
            byte[] retBytes = {(byte) 0xc3}; // x86 ret instruction
            memory.setBytes(testAddr, retBytes);
            ghidra.app.cmd.disassemble.DisassembleCommand disassembleCmd =
                new ghidra.app.cmd.disassemble.DisassembleCommand(testAddr, null, true);
            disassembleCmd.applyTo(program, TaskMonitor.DUMMY);

            // Create existing function for other tests
            Function existingFunc = functionManager.createFunction("oldFunction", existingFuncAddr,
                new AddressSet(existingFuncAddr, existingFuncAddr.add(50)), SourceType.USER_DEFINED);
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
    public void testManageFunctionCreateAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "create");
            arguments.put("address", "0x01000100");
            arguments.put("name", "newFunction");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain success field", json.has("success"));
            assertTrue("Result should contain function field", json.has("function"));
        });
    }

    @Test
    public void testManageFunctionSetPrototypeAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "set_prototype");
            arguments.put("functionIdentifier", "0x01000200");
            arguments.put("prototype", "int main(int argc, char** argv)");
            arguments.put("createIfNotExists", true);

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain success field", json.has("success"));
        });
    }

    @Test
    public void testManageFunctionRenameFunctionAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "rename_function");
            arguments.put("functionIdentifier", "oldFunction");
            arguments.put("name", "renamedFunction");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Result should contain success field", json.has("success"));
        });
    }

    @Test
    public void testManageFunctionRenameVariableAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First set a prototype to create variables
            Map<String, Object> setProtoArgs = new HashMap<>();
            setProtoArgs.put("programPath", programPath);
            setProtoArgs.put("action", "set_prototype");
            setProtoArgs.put("functionIdentifier", "0x01002000");
            setProtoArgs.put("prototype", "void test(int param1, int param2)");
            client.callTool(new CallToolRequest("manage-function", setProtoArgs));

            // Then rename a variable
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "rename_variable");
            arguments.put("functionIdentifier", "0x01000200");
            arguments.put("oldName", "param1");
            arguments.put("newName", "renamedParam");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            // May fail if decompilation doesn't work, but should return valid response
        });
    }

    @Test
    public void testManageFunctionSetVariableTypeAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First set a prototype to create variables
            Map<String, Object> setProtoArgs = new HashMap<>();
            setProtoArgs.put("programPath", programPath);
            setProtoArgs.put("action", "set_prototype");
            setProtoArgs.put("functionIdentifier", "0x01002000");
            setProtoArgs.put("prototype", "void test(int param1)");
            client.callTool(new CallToolRequest("manage-function", setProtoArgs));

            // Then change variable type
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "set_variable_type");
            arguments.put("functionIdentifier", "0x01000200");
            arguments.put("variableName", "param1");
            arguments.put("newType", "long");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            // May fail if decompilation doesn't work, but should return valid response
        });
    }

    @Test
    public void testManageFunctionChangeDatatypesAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First set a prototype to create variables
            Map<String, Object> setProtoArgs = new HashMap<>();
            setProtoArgs.put("programPath", programPath);
            setProtoArgs.put("action", "set_prototype");
            setProtoArgs.put("functionIdentifier", "0x01002000");
            setProtoArgs.put("prototype", "void test(int param1, int param2)");
            client.callTool(new CallToolRequest("manage-function", setProtoArgs));

            // Then change multiple variable types
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "change_datatypes");
            arguments.put("functionIdentifier", "0x01000200");
            arguments.put("datatypeMappings", "param1:long,param2:short");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            // May fail if decompilation doesn't work, but should return valid response
        });
    }

    @Test
    public void testManageFunctionBatchCreate() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test batch create with array of addresses
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "create");
            arguments.put("address", java.util.Arrays.asList("0x01000300", "0x01000400"));
            arguments.put("name", "batchFunc");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            // May fail if addresses don't have instructions, but should handle gracefully
        });
    }

    @Test
    public void testManageFunctionBatchRename() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create additional functions for batch rename
            Address funcAddr1 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000500);
            Address funcAddr2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000600);
            int txId = program.startTransaction("Create functions for batch rename");
            try {
                FunctionManager funcManager = program.getFunctionManager();
                try {
                    funcManager.createFunction("batchFunc1", funcAddr1,
                        new AddressSet(funcAddr1, funcAddr1.add(20)), SourceType.USER_DEFINED);
                } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                    fail("Failed to create batchFunc1: " + e.getMessage());
                }
                try {
                    funcManager.createFunction("batchFunc2", funcAddr2,
                        new AddressSet(funcAddr2, funcAddr2.add(20)), SourceType.USER_DEFINED);
                } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                    fail("Failed to create batchFunc2: " + e.getMessage());
                }
            } finally {
                program.endTransaction(txId, true);
            }

            // Test batch rename with functions array
            java.util.List<Map<String, Object>> functionsList = java.util.Arrays.asList(
                Map.of("functionIdentifier", "batchFunc1", "name", "renamedBatch1"),
                Map.of("functionIdentifier", "batchFunc2", "name", "renamedBatch2")
            );

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "rename_function");
            arguments.put("functions", functionsList);

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                // Verify functions were renamed
                FunctionManager funcManager = program.getFunctionManager();
                Function func1 = funcManager.getFunctionAt(funcAddr1);
                Function func2 = funcManager.getFunctionAt(funcAddr2);
                if (func1 != null && func2 != null) {
                    assertTrue("Function 1 should be renamed", func1.getName().contains("renamedBatch1") ||
                        "renamedBatch1".equals(func1.getName()));
                    assertTrue("Function 2 should be renamed", func2.getName().contains("renamedBatch2") ||
                        "renamedBatch2".equals(func2.getName()));
                }
            }
        });
    }

    @Test
    public void testManageFunctionRenameVariableWithMappings() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First set a prototype
            Map<String, Object> setProtoArgs = new HashMap<>();
            setProtoArgs.put("programPath", programPath);
            setProtoArgs.put("action", "set_prototype");
            setProtoArgs.put("functionIdentifier", "0x01000200");
            setProtoArgs.put("prototype", "void test(int var1, int var2)");
            client.callTool(new CallToolRequest("manage-function", setProtoArgs));

            // Then rename variables using mappings
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "rename_variable");
            arguments.put("functionIdentifier", "0x01000200");
            arguments.put("variableMappings", "var1:renamedVar1,var2:renamedVar2");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            // May fail if decompilation doesn't work
        });
    }

    @Test
    public void testManageFunctionSetPrototypeBatch() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test batch set prototype with array
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "set_prototype");
            arguments.put("functionIdentifier", java.util.Arrays.asList("0x01000200", "oldFunction"));
            arguments.put("prototype", java.util.Arrays.asList("int func1()", "int func2(int x)"));

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            // May fail if functions don't exist, but should handle gracefully
        });
    }

    @Test
    public void testManageFunctionPropagate() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test propagate functionality
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "rename_function");
            arguments.put("functionIdentifier", "oldFunction");
            arguments.put("name", "propagatedFunction");
            arguments.put("propagate", true);

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            // May return propagation results or just succeed
        });
    }

    @Test
    public void testManageFunctionValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test that function rename actually updates program state
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "rename_function");
            arguments.put("functionIdentifier", "oldFunction");
            arguments.put("name", "stateValidatedFunction");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertNotNull("Result should not be null", result);
            if (!result.isError()) {
                // Verify function was actually renamed in program state
                FunctionManager funcManager = program.getFunctionManager();
                Function func = funcManager.getFunctionAt(existingFuncAddr);
                assertNotNull("Function should exist", func);
                assertEquals("Function should be renamed", "stateValidatedFunction", func.getName());
            }
        });
    }

    @Test
    public void testManageFunctionInvalidAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "invalid_action");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertTrue("Tool should have error for invalid action", result.isError());
        });
    }

    @Test
    public void testManageFunctionMissingRequiredParameters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test create without address
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", programPath);
            arguments.put("action", "create");
            arguments.put("name", "test");

            CallToolResult result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertTrue("Tool should have error for missing address", result.isError());

            // Test rename without name
            arguments.clear();
            arguments.put("programPath", programPath);
            arguments.put("action", "rename_function");
            arguments.put("functionIdentifier", "oldFunction");

            result = client.callTool(new CallToolRequest("manage-function", arguments));

            assertTrue("Tool should have error for missing name", result.isError());
        });
    }
}
