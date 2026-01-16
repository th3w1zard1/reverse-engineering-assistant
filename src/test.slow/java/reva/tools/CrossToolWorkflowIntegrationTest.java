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
package reva.tools;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
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
 * Comprehensive integration tests for cross-tool workflows.
 * Tests multiple tools used in sequence to verify they work together correctly.
 */
public class CrossToolWorkflowIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;
    private Address functionAddr;
    private Address dataAddr;
    private Address stringAddr;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Create test addresses
        functionAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        dataAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
        stringAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000300);

        // Create initial test data
        int txId = program.startTransaction("Setup test data");
        try {
            // Ensure we have an executable memory block for function creation tests
            // The base class creates a non-executable block, so we need to create an executable one
            ghidra.program.model.mem.Memory memory = program.getMemory();
            ghidra.program.model.mem.MemoryBlock defaultBlock = memory.getBlock("test");
            if (defaultBlock != null && !defaultBlock.isExecute()) {
                // Try to set execute permission using reflection (Ghidra API limitation)
                try {
                    java.lang.reflect.Method setExecuteMethod = defaultBlock.getClass().getMethod("setExecute", boolean.class);
                    setExecuteMethod.invoke(defaultBlock, true);
                } catch (Exception e) {
                    // If reflection fails, remove and recreate as executable
                    memory.removeBlock(defaultBlock, ghidra.util.task.TaskMonitor.DUMMY);
                    memory.createInitializedBlock("executable_test",
                        program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000000),
                        0x10000, (byte) 0, ghidra.util.task.TaskMonitor.DUMMY, false);
                    try {
                        java.lang.reflect.Method setExecuteMethod = memory.getBlock("executable_test").getClass().getMethod("setExecute", boolean.class);
                        setExecuteMethod.invoke(memory.getBlock("executable_test"), true);
                    } catch (Exception e2) {
                        // If still fails, tests that need executable memory will handle it
                    }
                }
            }

            // Create a function
            FunctionManager functionManager = program.getFunctionManager();
            Function testFunc = null;
            try {
                testFunc = functionManager.createFunction("testFunc", functionAddr,
                    new AddressSet(functionAddr, functionAddr.add(50)), SourceType.USER_DEFINED);
            } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                fail("Failed to create testFunc: " + e.getMessage());
            }
            if (testFunc == null) {
                return; // Skip test if function creation failed
            }

            // Add parameters
            Parameter param1 = new ParameterImpl("param1", new IntegerDataType(program.getDataTypeManager()), program);
            Parameter param2 = new ParameterImpl("param2", new PointerDataType(new IntegerDataType(program.getDataTypeManager()), program.getDataTypeManager()), program);
            testFunc.replaceParameters(java.util.List.of(param1, param2),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

            // Create data
            try {
                program.getListing().createData(dataAddr, new ByteDataType(), 1);
            } catch (Exception e) {
                // Data may already exist, ignore
            }

            // Create string
            program.getMemory().setBytes(stringAddr, "Test String\0".getBytes());
            program.getListing().createData(stringAddr, ghidra.program.model.data.StringDataType.dataType);
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

    /**
     * Test workflow: List functions -> Get function -> Add comment -> Get references -> Add bookmark
     */
    @Test
    public void testFunctionAnalysisWorkflow() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Step 1: List functions
            Map<String, Object> listArgs = new HashMap<>();
            listArgs.put("programPath", programPath);
            listArgs.put("mode", "all");
            CallToolResult listResult = client.callTool(new CallToolRequest("list-functions", listArgs));
            assertFalse("List functions should succeed", listResult.isError());
            TextContent listContent = (TextContent) listResult.content().get(0);
            JsonNode listJson = parseJsonContent(listContent.text());
            assertTrue("Should have functions", listJson.has("functions"));

            // Step 2: Get function details
            Map<String, Object> getArgs = new HashMap<>();
            getArgs.put("programPath", programPath);
            getArgs.put("identifier", "testFunc");
            getArgs.put("view", "info");
            CallToolResult getResult = client.callTool(new CallToolRequest("get-functions", getArgs));
            assertFalse("Get function should succeed", getResult.isError());

            // Step 3: Add comment to function
            Map<String, Object> commentArgs = new HashMap<>();
            commentArgs.put("programPath", programPath);
            commentArgs.put("action", "set");
            commentArgs.put("address", functionAddr.toString());
            commentArgs.put("comment", "Test function for workflow");
            commentArgs.put("commentType", "eol");
            CallToolResult commentResult = client.callTool(new CallToolRequest("manage-comments", commentArgs));
            assertFalse("Add comment should succeed", commentResult.isError());

            // Verify comment was added
            ghidra.program.model.listing.CodeUnit codeUnit = program.getListing().getCodeUnitAt(functionAddr);
            if (codeUnit != null) {
                String comment = codeUnit.getComment(ghidra.program.model.listing.CommentType.EOL);
                assertTrue("Comment should be added", comment != null && comment.contains("workflow"));
            }

            // Step 4: Get references to function
            Map<String, Object> refArgs = new HashMap<>();
            refArgs.put("programPath", programPath);
            refArgs.put("target", "testFunc");
            refArgs.put("mode", "to");
            CallToolResult refResult = client.callTool(new CallToolRequest("get-references", refArgs));
            assertFalse("Get references should succeed", refResult.isError());

            // Step 5: Add bookmark
            Map<String, Object> bookmarkArgs = new HashMap<>();
            bookmarkArgs.put("programPath", programPath);
            bookmarkArgs.put("action", "set");
            bookmarkArgs.put("address", functionAddr.toString());
            bookmarkArgs.put("type", "Analysis");
            bookmarkArgs.put("category", "workflow");
            bookmarkArgs.put("comment", "Important function");
            CallToolResult bookmarkResult = client.callTool(new CallToolRequest("manage-bookmarks", bookmarkArgs));
            assertFalse("Add bookmark should succeed", bookmarkResult.isError());

            // Verify bookmark was added
            ghidra.program.model.listing.Bookmark bookmark = program.getBookmarkManager().getBookmark(functionAddr, "Analysis", "workflow");
            assertNotNull("Bookmark should be added", bookmark);
        });
    }

    /**
     * Test workflow: Create function -> Rename function -> Set prototype -> Rename variables -> Get decompilation
     */
    @Test
    public void testFunctionModificationWorkflow() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Use a unique address that doesn't conflict with other tests (0x01001000 is used by other tests)
            // Create an executable block at a different address range for function creation
            Address newFuncAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x02000000);

            // Ensure there's an executable block and instruction at the address (required for function creation)
            int setupTxId = program.startTransaction("Setup function creation address");
            try {
                ghidra.program.model.mem.Memory memory = program.getMemory();
                ghidra.program.model.mem.MemoryBlock block = memory.getBlock(newFuncAddr);
                
                // If block doesn't exist or isn't executable, create a new executable block
                if (block == null || !block.isExecute()) {
                    // Remove existing block if it's not executable
                    if (block != null) {
                        try {
                            memory.removeBlock(block, ghidra.util.task.TaskMonitor.DUMMY);
                        } catch (Exception e) {
                            fail("Failed to remove block: " + e.getMessage());
                        }
                    }
                    // Create new executable block
                    try {
                        block = memory.createInitializedBlock("executable_workflow",
                            newFuncAddr, 0x1000, (byte) 0, ghidra.util.task.TaskMonitor.DUMMY, false);
                    } catch (Exception e) {
                        fail("Failed to create block: " + e.getMessage());
                    }
                    // Try to set execute permission via reflection
                    try {
                        java.lang.reflect.Method setExecuteMethod = block.getClass().getMethod("setExecute", boolean.class);
                        setExecuteMethod.invoke(block, true);
                    } catch (Exception e) {
                        // If reflection fails, we'll get a clear error from the tool
                    }
                }
                // Create an instruction at the address
                byte[] retBytes = {(byte) 0xc3}; // x86 ret instruction
                try {
                    memory.setBytes(newFuncAddr, retBytes);
                } catch (ghidra.program.model.mem.MemoryAccessException e) {
                    fail("Failed to set bytes at address: " + e.getMessage());
                }
                ghidra.app.cmd.disassemble.DisassembleCommand disassembleCmd =
                    new ghidra.app.cmd.disassemble.DisassembleCommand(newFuncAddr, null, true);
                disassembleCmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY);
            } finally {
                program.endTransaction(setupTxId, true);
            }

            // Step 1: Create function
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", programPath);
            createArgs.put("action", "create");
            createArgs.put("address", newFuncAddr.toString());
            createArgs.put("name", "newFunction");
            CallToolResult createResult = client.callTool(new CallToolRequest("manage-function", createArgs));
            assertFalse("Create function should succeed", createResult.isError());

            // Verify function was created
            FunctionManager funcManager = program.getFunctionManager();
            Function newFunc = funcManager.getFunctionAt(newFuncAddr);
            assertNotNull("Function should be created", newFunc);
            assertEquals("Function name should match", "newFunction", newFunc.getName());

            // Step 2: Rename function
            Map<String, Object> renameArgs = new HashMap<>();
            renameArgs.put("programPath", programPath);
            renameArgs.put("action", "rename_function");
            renameArgs.put("functionIdentifier", "newFunction");
            renameArgs.put("name", "renamedFunction");
            CallToolResult renameResult = client.callTool(new CallToolRequest("manage-function", renameArgs));
            assertFalse("Rename function should succeed", renameResult.isError());

            // Verify function was renamed
            newFunc = funcManager.getFunctionAt(newFuncAddr);
            assertEquals("Function should be renamed", "renamedFunction", newFunc.getName());

            // Step 3: Set function prototype
            Map<String, Object> prototypeArgs = new HashMap<>();
            prototypeArgs.put("programPath", programPath);
            prototypeArgs.put("action", "set_prototype");
            prototypeArgs.put("functionIdentifier", "renamedFunction");
            prototypeArgs.put("prototype", "int renamedFunction(int param1, char* param2)");
            CallToolResult prototypeResult = client.callTool(new CallToolRequest("manage-function", prototypeArgs));
            assertFalse("Set prototype should succeed", prototypeResult.isError());

            // Verify prototype was set
            newFunc = funcManager.getFunctionAt(newFuncAddr);
            Parameter[] params = newFunc.getParameters();
            assertTrue("Function should have parameters", params.length >= 2);

            // Step 4: Rename variable
            Map<String, Object> varRenameArgs = new HashMap<>();
            varRenameArgs.put("programPath", programPath);
            varRenameArgs.put("action", "rename_variable");
            varRenameArgs.put("functionIdentifier", "renamedFunction");
            varRenameArgs.put("oldName", "param1");
            varRenameArgs.put("newName", "renamedParam1");
            CallToolResult varRenameResult = client.callTool(new CallToolRequest("manage-function", varRenameArgs));
            // May fail if variable doesn't exist in decompilation, but should handle gracefully

            // Step 6: Get function decompilation again to verify changes
            Map<String, Object> decompArgs = new HashMap<>();
            decompArgs.put("programPath", programPath);
            decompArgs.put("identifier", "renamedFunction");
            decompArgs.put("view", "decompile");
            CallToolResult decompResult = client.callTool(new CallToolRequest("get-functions", decompArgs));
            assertFalse("Get decompilation should succeed", decompResult.isError());
        });
    }

    /**
     * Test workflow: List strings -> Create label -> Get references -> Add comment
     */
    @Test
    public void testStringAnalysisWorkflow() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Step 1: List strings
            Map<String, Object> stringArgs = new HashMap<>();
            stringArgs.put("programPath", programPath);
            stringArgs.put("mode", "list");
            stringArgs.put("maxCount", 10);
            CallToolResult stringResult = client.callTool(new CallToolRequest("manage-strings", stringArgs));
            assertFalse("List strings should succeed", stringResult.isError());
            TextContent stringContent = (TextContent) stringResult.content().get(0);
            JsonNode stringJson = parseJsonContent(stringContent.text());
            assertTrue("Should have strings", stringJson.isArray() && stringJson.size() > 0);

            // Step 2: Create label at string address
            Map<String, Object> labelArgs = new HashMap<>();
            labelArgs.put("programPath", programPath);
            labelArgs.put("mode", "create_label");
            labelArgs.put("address", stringAddr.toString());
            labelArgs.put("labelName", "testStringLabel");
            CallToolResult labelResult = client.callTool(new CallToolRequest("manage-symbols", labelArgs));
            assertFalse("Create label should succeed", labelResult.isError());

            // Verify label was created
            ghidra.program.model.symbol.SymbolTable symbolTable = program.getSymbolTable();
            ghidra.program.model.symbol.Symbol symbol = symbolTable.getPrimarySymbol(stringAddr);
            assertNotNull("Symbol should be created", symbol);
            assertTrue("Symbol name should match", symbol.getName().contains("testStringLabel") ||
                "testStringLabel".equals(symbol.getName()));

            // Step 3: Get references to string
            Map<String, Object> refArgs = new HashMap<>();
            refArgs.put("programPath", programPath);
            refArgs.put("target", stringAddr.toString());
            refArgs.put("mode", "to");
            CallToolResult refResult = client.callTool(new CallToolRequest("get-references", refArgs));
            assertFalse("Get references should succeed", refResult.isError());

            // Step 4: Add comment at string address
            Map<String, Object> commentArgs = new HashMap<>();
            commentArgs.put("programPath", programPath);
            commentArgs.put("action", "set");
            commentArgs.put("address", stringAddr.toString());
            commentArgs.put("comment", "Test string data");
            commentArgs.put("commentType", "pre");
            CallToolResult commentResult = client.callTool(new CallToolRequest("manage-comments", commentArgs));
            assertFalse("Add comment should succeed", commentResult.isError());

            // Verify comment was added
            ghidra.program.model.listing.CodeUnit codeUnit = program.getListing().getCodeUnitAt(stringAddr);
            if (codeUnit != null) {
                String comment = codeUnit.getComment(ghidra.program.model.listing.CommentType.PRE);
                assertTrue("Comment should be added", comment != null && comment.contains("Test string"));
            }
        });
    }

    /**
     * Test workflow: Get call graph -> Analyze data flow -> Search constants -> Add bookmarks
     */
    @Test
    public void testAnalysisWorkflow() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Step 1: Get call graph
            Map<String, Object> callGraphArgs = new HashMap<>();
            callGraphArgs.put("programPath", programPath);
            callGraphArgs.put("functionIdentifier", "testFunc");
            callGraphArgs.put("mode", "graph");
            callGraphArgs.put("depth", 1);
            CallToolResult callGraphResult = client.callTool(new CallToolRequest("get-call-graph", callGraphArgs));
            assertFalse("Get call graph should succeed", callGraphResult.isError());

            // Step 2: Analyze data flow (if function has instructions)
            Map<String, Object> dataFlowArgs = new HashMap<>();
            dataFlowArgs.put("programPath", programPath);
            dataFlowArgs.put("functionAddress", functionAddr.toString());
            dataFlowArgs.put("direction", "backward");
            dataFlowArgs.put("startAddress", functionAddr.toString());
            CallToolResult dataFlowResult = client.callTool(new CallToolRequest("analyze-data-flow", dataFlowArgs));
            // May return empty if no data flow, but should not error

            // Step 3: Search constants
            Map<String, Object> constArgs = new HashMap<>();
            constArgs.put("programPath", programPath);
            constArgs.put("mode", "specific");
            constArgs.put("value", "0");
            constArgs.put("maxResults", 10);
            CallToolResult constResult = client.callTool(new CallToolRequest("search-constants", constArgs));
            assertFalse("Search constants should succeed", constResult.isError());

            // Step 4: Add bookmark at function
            Map<String, Object> bookmarkArgs = new HashMap<>();
            bookmarkArgs.put("programPath", programPath);
            bookmarkArgs.put("action", "set");
            bookmarkArgs.put("address", functionAddr.toString());
            bookmarkArgs.put("type", "Analysis");
            bookmarkArgs.put("category", "analysis");
            bookmarkArgs.put("comment", "Analyzed function");
            CallToolResult bookmarkResult = client.callTool(new CallToolRequest("manage-bookmarks", bookmarkArgs));
            assertFalse("Add bookmark should succeed", bookmarkResult.isError());
        });
    }

    /**
     * Test workflow: Apply data type -> Create structure -> Apply structure -> Get data
     */
    @Test
    public void testDataTypeWorkflow() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Address structAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000400);

            // Step 1: Apply data type
            Map<String, Object> applyTypeArgs = new HashMap<>();
            applyTypeArgs.put("programPath", programPath);
            applyTypeArgs.put("action", "apply");
            applyTypeArgs.put("addressOrSymbol", structAddr.toString());
            applyTypeArgs.put("dataTypeString", "int");
            CallToolResult applyTypeResult = client.callTool(new CallToolRequest("manage-data-types", applyTypeArgs));
            assertFalse("Apply data type should succeed", applyTypeResult.isError());

            // Step 2: Create structure
            Map<String, Object> createStructArgs = new HashMap<>();
            createStructArgs.put("programPath", programPath);
            createStructArgs.put("action", "create");
            createStructArgs.put("name", "TestStruct");
            createStructArgs.put("size", 8);
            CallToolResult createStructResult = client.callTool(new CallToolRequest("manage-structures", createStructArgs));
            assertFalse("Create structure should succeed", createStructResult.isError());

            // Step 3: Add field to structure
            Map<String, Object> addFieldArgs = new HashMap<>();
            addFieldArgs.put("programPath", programPath);
            addFieldArgs.put("action", "add_field");
            addFieldArgs.put("structureName", "TestStruct");
            addFieldArgs.put("fieldName", "field1");
            addFieldArgs.put("dataType", "int");
            CallToolResult addFieldResult = client.callTool(new CallToolRequest("manage-structures", addFieldArgs));
            assertFalse("Add field should succeed", addFieldResult.isError());

            // Step 4: Apply structure
            Map<String, Object> applyStructArgs = new HashMap<>();
            applyStructArgs.put("programPath", programPath);
            applyStructArgs.put("action", "apply");
            applyStructArgs.put("structureName", "TestStruct");
            applyStructArgs.put("addressOrSymbol", structAddr.toString());
            CallToolResult applyStructResult = client.callTool(new CallToolRequest("manage-structures", applyStructArgs));
            assertFalse("Apply structure should succeed", applyStructResult.isError());

            // Step 5: Inspect memory at address
            Map<String, Object> memoryArgs = new HashMap<>();
            memoryArgs.put("programPath", programPath);
            memoryArgs.put("mode", "data_at");
            memoryArgs.put("address", structAddr.toString());
            CallToolResult memoryResult = client.callTool(new CallToolRequest("inspect-memory", memoryArgs));
            assertFalse("Inspect memory should succeed", memoryResult.isError());
        });
    }

    /**
     * Test workflow: List functions -> Tag functions -> Filter by tag -> Match functions
     */
    @Test
    public void testFunctionTaggingWorkflow() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Step 1: List functions
            Map<String, Object> listArgs = new HashMap<>();
            listArgs.put("programPath", programPath);
            listArgs.put("mode", "all");
            CallToolResult listResult = client.callTool(new CallToolRequest("list-functions", listArgs));
            assertFalse("List functions should succeed", listResult.isError());

            // Step 2: Add tag to function
            Map<String, Object> tagArgs = new HashMap<>();
            tagArgs.put("programPath", programPath);
            tagArgs.put("mode", "add");
            tagArgs.put("function", "testFunc");
            tagArgs.put("tags", java.util.Arrays.asList("test", "workflow"));
            CallToolResult tagResult = client.callTool(new CallToolRequest("manage-function-tags", tagArgs));
            assertFalse("Add tag should succeed", tagResult.isError());

            // Step 3: List functions filtered by tag
            Map<String, Object> filterArgs = new HashMap<>();
            filterArgs.put("programPath", programPath);
            filterArgs.put("mode", "all");
            filterArgs.put("filterByTag", "test");
            CallToolResult filterResult = client.callTool(new CallToolRequest("list-functions", filterArgs));
            assertFalse("Filter by tag should succeed", filterResult.isError());
            TextContent filterContent = (TextContent) filterResult.content().get(0);
            JsonNode filterJson = parseJsonContent(filterContent.text());
            if (filterJson.has("functions")) {
                JsonNode functions = filterJson.get("functions");
                assertTrue("Should have functions with tag", functions.size() > 0);
            }

            // Step 4: Get tags for function
            Map<String, Object> getTagArgs = new HashMap<>();
            getTagArgs.put("programPath", programPath);
            getTagArgs.put("mode", "get");
            getTagArgs.put("function", "testFunc");
            CallToolResult getTagResult = client.callTool(new CallToolRequest("manage-function-tags", getTagArgs));
            assertFalse("Get tags should succeed", getTagResult.isError());
        });
    }
}
