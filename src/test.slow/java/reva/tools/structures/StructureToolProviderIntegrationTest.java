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
package reva.tools.structures;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ListToolsResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for StructureToolProvider
 */
public class StructureToolProviderIntegrationTest extends RevaIntegrationTestBase {
    private String program_path;

    @Before
    public void setUpStructureTests() throws Exception {
        // Get program path for use in tests - this is how RevaProgramManager identifies programs
        program_path = program.getDomainFile().getPathname();

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
    }

    @Test
    public void testListToolsIncludesStructureTools() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            ListToolsResult tools = client.listTools(null);
            assertNotNull("Tools result should not be null", tools);
            assertNotNull("Tools list should not be null", tools.tools());

            // Look for our consolidated structure tool
            boolean foundManageStructures = false;

            for (Tool tool : tools.tools()) {
                if ("manage-structures".equals(tool.name())) {
                    foundManageStructures = true;
                }
            }

            assertTrue("manage-structures tool should be available", foundManageStructures);
        });
    }

    @Test
    public void testParseCStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("action", "parse");
            arguments.put("cDefinition", "struct TestStruct { int field1; char field2[32]; };");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            // Parse the JSON content
            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("TestStruct", json.get("name").asText());
            assertEquals("Successfully created structure: TestStruct", json.get("message").asText());

            // Verify structure was created in program
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "TestStruct");
            assertNotNull("Structure should exist in program", dt);
            assertTrue("Should be a Structure", dt instanceof Structure);

            Structure struct = (Structure) dt;
            assertEquals("Should have 2 components", 2, struct.getNumComponents());
        });
    }

    @Test
    public void testValidateCStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test valid structure
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("action", "validate");
            arguments.put("cDefinition", "struct ValidStruct { int x; int y; };");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should be valid", json.get("valid").asBoolean());
            assertEquals("ValidStruct", json.get("parsedType").asText());

            // Test invalid structure
            arguments.put("cDefinition", "struct InvalidStruct { unknown_type field; };");
            result = client.callTool(new CallToolRequest("manage-structures", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            content = (TextContent) result.content().get(0);
            json = parseJsonContent(content.text());

            assertFalse("Should be invalid", json.get("valid").asBoolean());
            assertNotNull("Should have error message", json.get("error"));
        });
    }

    @Test
    public void testCreateEmptyStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("action", "create");
            arguments.put("name", "EmptyStruct");
            arguments.put("size", 0);
            arguments.put("type", "structure");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", arguments));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("EmptyStruct", json.get("name").asText());
            assertFalse("Should not be a union", 
                json.has("is_union") ? json.get("is_union").asBoolean() : json.get("isUnion").asBoolean());

            // Verify structure exists
            DataType dt = findDataTypeByName(program.getDataTypeManager(), "EmptyStruct");
            assertNotNull("Structure should exist", dt);
        });
    }

    @Test
    public void testAddStructureField() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First create a structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "create");
            createArgs.put("name", "TestFieldStruct");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Create structure should not error");

            // Add a field
            Map<String, Object> addArgs = new HashMap<>();
            addArgs.put("programPath", program_path);
            addArgs.put("action", "add_field");
            addArgs.put("structureName", "TestFieldStruct");
            addArgs.put("fieldName", "myField");
            addArgs.put("dataType", "int");
            addArgs.put("comment", "Test field");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", addArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("Successfully added field: myField", json.get("message").asText());

            // Verify field was added
            DataType dt = findDataTypeByName(program.getDataTypeManager(), "TestFieldStruct");
            Structure struct = (Structure) dt;
            assertEquals("Should have 1 component", 1, struct.getNumComponents());
            assertEquals("myField", struct.getComponent(0).getFieldName());
        });
    }

    @Test
    public void testGetStructureInfo() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure with fields
            Map<String, Object> args = new HashMap<>();
            args.put("programPath", program_path);
            args.put("action", "parse");
            args.put("cDefinition", "struct InfoStruct { int id; char name[20]; void* next; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", args));
            assertMcpResultNotError(createResult, "Create structure should not error");

            // Get structure info
            Map<String, Object> infoArgs = new HashMap<>();
            infoArgs.put("programPath", program_path);
            infoArgs.put("action", "info");
            infoArgs.put("structureName", "InfoStruct");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", infoArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertEquals("InfoStruct", json.get("name").asText());
            assertEquals(3, json.has("numComponents") ? json.get("numComponents").asInt() : json.get("num_components").asInt());

            JsonNode fields = json.get("fields");
            assertNotNull("Should have fields", fields);
            assertEquals("Should have 3 fields", 3, fields.size());

            // Check first field
            JsonNode firstField = fields.get(0);
            assertEquals("id", firstField.get("fieldName").asText());
            assertEquals("int", firstField.get("dataType").asText());
        });
    }

    @Test
    public void testListStructures() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create multiple structures
            String[] structDefs = {
                "struct Struct1 { int a; };",
                "struct Struct2 { char b; };",
                "union Union1 { int x; float y; };"
            };

            for (String def : structDefs) {
                Map<String, Object> args = new HashMap<>();
                args.put("programPath", program_path);
                args.put("action", "parse");
                args.put("cDefinition", def);
                CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", args));
                assertMcpResultNotError(createResult, "Create structure should not error: " + def);
            }

            // List structures
            Map<String, Object> listArgs = new HashMap<>();
            listArgs.put("programPath", program_path);
            listArgs.put("action", "list");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", listArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode structures = json.get("structures");

            // Should have at least the 3 we created
            assertTrue("Should have at least 3 structures", structures.size() >= 3);

            // Verify our structures are in the list
            boolean foundStruct1 = false, foundStruct2 = false, foundUnion1 = false;
            for (JsonNode struct : structures) {
                String name = struct.get("name").asText();
                if ("Struct1".equals(name)) foundStruct1 = true;
                if ("Struct2".equals(name)) foundStruct2 = true;
                if ("Union1".equals(name)) foundUnion1 = true;
            }

            assertTrue("Should find Struct1", foundStruct1);
            assertTrue("Should find Struct2", foundStruct2);
            assertTrue("Should find Union1", foundUnion1);
        });
    }

    @Test
    public void testDeleteStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "create");
            createArgs.put("name", "ToBeDeleted");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Create structure should not error");

            // Verify it exists
            DataType dt = findDataTypeByName(program.getDataTypeManager(), "ToBeDeleted");
            assertNotNull("Structure should exist before deletion", dt);

            // Delete it
            Map<String, Object> deleteArgs = new HashMap<>();
            deleteArgs.put("programPath", program_path);
            deleteArgs.put("action", "delete");
            deleteArgs.put("structureName", "ToBeDeleted");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", deleteArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should be deleted", json.get("deleted").asBoolean());

            // Verify it's gone
            dt = findDataTypeByName(program.getDataTypeManager(), "ToBeDeleted");
            assertNull("Structure should not exist after deletion", dt);
        });
    }

    @Test
    public void testParseCHeader() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String headerContent =
                "struct Point { int x; int y; };\n" +
                "struct Rectangle { int width; int height; };";

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", program_path);
            args.put("action", "parse_header");
            args.put("headerContent", headerContent);

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode createdTypes = json.has("created_types") ? json.get("created_types") : json.get("createdTypes");
            assertNotNull("Should have createdTypes field", createdTypes);
            assertTrue("Should create at least one type", createdTypes.size() >= 1);

            // Verify at least one structure was created
            DataTypeManager dtm = program.getDataTypeManager();
            DataType point = findDataTypeByName(dtm, "Point");
            DataType rectangle = findDataTypeByName(dtm, "Rectangle");

            assertTrue("At least one structure (Point or Rectangle) should exist",
                point != null || rectangle != null);
        });
    }

    @Test
    public void testComplexNestedStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            String complexDef =
                "struct Node {\n" +
                "    int value;\n" +
                "    struct Node* left;\n" +
                "    struct Node* right;\n" +
                "    union {\n" +
                "        int intData;\n" +
                "        float floatData;\n" +
                "    } data;\n" +
                "};";

            Map<String, Object> args = new HashMap<>();
            args.put("programPath", program_path);
            args.put("action", "parse");
            args.put("cDefinition", complexDef);

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", args));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            // Get detailed info
            Map<String, Object> infoArgs = new HashMap<>();
            infoArgs.put("programPath", program_path);
            infoArgs.put("action", "info");
            infoArgs.put("structureName", "Node");

            result = client.callTool(new CallToolRequest("manage-structures", infoArgs));

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("Should have C representation", 
                json.has("c_representation") || json.has("cRepresentation"));
            int numComponents = json.has("num_components") 
                ? json.get("num_components").asInt() 
                : json.get("numComponents").asInt();
            assertEquals("Should have 4 components", 4, numComponents);
        });
    }

    @Test
    public void testGetStructureInfoCondensesUndefinedBytes() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure with a specific size that will have many undefined bytes
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "create");
            createArgs.put("name", "LargeStruct");
            createArgs.put("size", 100); // 100 bytes

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Create structure should not error");

            // Add just a few defined fields, leaving many undefined bytes
            Map<String, Object> addArgs1 = new HashMap<>();
            addArgs1.put("programPath", program_path);
            addArgs1.put("action", "add_field");
            addArgs1.put("structureName", "LargeStruct");
            addArgs1.put("fieldName", "firstField");
            addArgs1.put("dataType", "int");
            addArgs1.put("offset", 0);

            client.callTool(new CallToolRequest("manage-structures", addArgs1));

            Map<String, Object> addArgs2 = new HashMap<>();
            addArgs2.put("programPath", program_path);
            addArgs2.put("action", "add_field");
            addArgs2.put("structureName", "LargeStruct");
            addArgs2.put("fieldName", "lastField");
            addArgs2.put("dataType", "int");
            addArgs2.put("offset", 96); // Near the end

            client.callTool(new CallToolRequest("manage-structures", addArgs2));

            // Get structure info
            Map<String, Object> infoArgs = new HashMap<>();
            infoArgs.put("programPath", program_path);
            infoArgs.put("action", "info");
            infoArgs.put("structureName", "LargeStruct");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", infoArgs));

            assertNotNull("Result should not be null", result);
            assertMcpResultNotError(result, "Result should not be an error");

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            JsonNode fields = json.get("fields");
            assertNotNull("Should have fields", fields);

            // Verify that undefined bytes were condensed
            // Should have: firstField, condensed undefined range, lastField
            // Instead of 100+ individual undefined byte fields
            assertTrue("Should have fewer than 10 fields due to condensing", fields.size() < 10);

            // Check for condensed field
            boolean foundCondensed = false;
            for (JsonNode field : fields) {
                if (field.has("isCondensed") && field.get("isCondensed").asBoolean()) {
                    foundCondensed = true;
                    assertEquals("<undefined>", field.get("fieldName").asText());
                    assertTrue("Condensed range should have componentCount > 1",
                        field.get("componentCount").asInt() > 1);
                }
            }

            assertTrue("Should have at least one condensed undefined range", foundCondensed);

            // Verify C representation is also condensed
            JsonNode cRepresentation = json.get("cRepresentation");
            assertNotNull("Should have C representation", cRepresentation);
            String cCode = cRepresentation.asText();

            // C representation should contain condensed undefined arrays
            assertTrue("C representation should contain condensed undefined ranges",
                cCode.contains("undefined reserved_0x"));
            assertTrue("C representation should show offset ranges in comments",
                cCode.contains("// 0x"));

            // Count lines in C representation (excluding struct declaration and closing brace)
            String[] cLines = cCode.split("\n");
            int fieldLines = 0;
            for (String line : cLines) {
                if (line.trim().endsWith(";")) {
                    fieldLines++;
                }
            }

            // Should have much fewer lines than the original 100 components
            assertTrue("C representation should have fewer than 20 lines due to condensing",
                fieldLines < 20);
        });
    }

    @Test
    public void testModifyStructureFieldDataType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First create a structure with a field
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "parse");
            createArgs.put("cDefinition", "struct ModifyTest1 { void *field1; int field2; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Verify initial structure
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "ModifyTest1");
            assertNotNull("Structure should exist", dt);
            Structure struct = (Structure) dt;
            assertEquals("Should have 2 fields", 2, struct.getNumComponents());

            // Verify field1 is void *
            ghidra.program.model.data.DataTypeComponent field1Before = struct.getComponent(0);
            assertEquals("field1", field1Before.getFieldName());
            assertTrue("field1 should be pointer", field1Before.getDataType().getName().contains("pointer") ||
                       field1Before.getDataType().getDisplayName().contains("*"));

            // Modify field1 to be int *
            Map<String, Object> modifyArgs = new HashMap<>();
            modifyArgs.put("programPath", program_path);
            modifyArgs.put("action", "modify_field");
            modifyArgs.put("structureName", "ModifyTest1");
            modifyArgs.put("fieldName", "field1");
            modifyArgs.put("newDataType", "int *");

            CallToolResult modifyResult = client.callTool(new CallToolRequest("manage-structures", modifyArgs));
            assertMcpResultNotError(modifyResult, "Field modification should succeed");

            TextContent content = (TextContent) modifyResult.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            String message = json.get("message").asText();
            assertTrue("Should indicate successful field modification", message.contains("Successfully modified field"));

            // Verify the field was actually modified in the program
            dt = findDataTypeByName(dtm, "ModifyTest1");
            struct = (Structure) dt;
            ghidra.program.model.data.DataTypeComponent field1After = struct.getComponent(0);
            assertEquals("field1", field1After.getFieldName());

            // Verify data type changed (int * instead of void *)
            String fieldTypeName = field1After.getDataType().getDisplayName();
            assertTrue("field1 should now be int pointer, got: " + fieldTypeName,
                       fieldTypeName.contains("int") && fieldTypeName.contains("*"));
        });
    }

    @Test
    public void testModifyStructureFieldName() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "parse");
            createArgs.put("cDefinition", "struct ModifyTest2 { int oldName; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Rename the field
            Map<String, Object> modifyArgs = new HashMap<>();
            modifyArgs.put("programPath", program_path);
            modifyArgs.put("action", "modify_field");
            modifyArgs.put("structureName", "ModifyTest2");
            modifyArgs.put("fieldName", "oldName");
            modifyArgs.put("newFieldName", "newName");

            CallToolResult modifyResult = client.callTool(new CallToolRequest("manage-structures", modifyArgs));
            assertMcpResultNotError(modifyResult, "Field rename should succeed");

            // Verify the field was renamed in the program
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "ModifyTest2");
            Structure struct = (Structure) dt;
            ghidra.program.model.data.DataTypeComponent field = struct.getComponent(0);
            assertEquals("Field should be renamed to newName", "newName", field.getFieldName());
        });
    }

    @Test
    public void testModifyStructureFieldByOffset() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "parse");
            createArgs.put("cDefinition", "struct ModifyTest3 { int field1; char field2; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Get offset of field2 (should be at offset 4 after the int)
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "ModifyTest3");
            Structure struct = (Structure) dt;
            int field2Offset = struct.getComponent(1).getOffset();

            // Modify field2 by offset instead of name
            Map<String, Object> modifyArgs = new HashMap<>();
            modifyArgs.put("programPath", program_path);
            modifyArgs.put("action", "modify_field");
            modifyArgs.put("structureName", "ModifyTest3");
            modifyArgs.put("fieldName", "field2");
            modifyArgs.put("offset", field2Offset);
            modifyArgs.put("newDataType", "short");

            CallToolResult modifyResult = client.callTool(new CallToolRequest("manage-structures", modifyArgs));
            assertMcpResultNotError(modifyResult, "Field modification by offset should succeed");

            // Verify the field was modified
            dt = findDataTypeByName(dtm, "ModifyTest3");
            struct = (Structure) dt;
            ghidra.program.model.data.DataTypeComponent field2 = struct.getComponentAt(field2Offset);
            assertEquals("field2", field2.getFieldName());
            assertTrue("field2 should now be short",
                       field2.getDataType().getName().contains("short"));
        });
    }

    @Test
    public void testModifyStructureFromC() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create initial structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "parse");
            createArgs.put("cDefinition", "struct ModifyTest4 { int field1; char field2; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Verify initial structure
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "ModifyTest4");
            Structure struct = (Structure) dt;
            assertEquals("Should have 2 fields initially", 2, struct.getNumComponents());

            // Modify structure using C definition
            Map<String, Object> modifyArgs = new HashMap<>();
            modifyArgs.put("programPath", program_path);
            modifyArgs.put("action", "modify_from_c");
            modifyArgs.put("cDefinition", "struct ModifyTest4 { int field1; short field2; long field3; };");

            CallToolResult modifyResult = client.callTool(new CallToolRequest("manage-structures", modifyArgs));
            assertMcpResultNotError(modifyResult, "Structure modification from C should succeed");

            TextContent content = (TextContent) modifyResult.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            String message = json.get("message").asText();
            assertTrue("Should indicate successful modification", message.contains("Successfully modified structure from C definition"));
            assertEquals(3, json.has("numComponents") ? json.get("numComponents").asInt() : json.get("num_components").asInt());

            // Verify the structure was modified in the program
            dt = findDataTypeByName(dtm, "ModifyTest4");
            struct = (Structure) dt;
            assertEquals("Should now have 3 fields", 3, struct.getNumComponents());

            // Verify field types
            ghidra.program.model.data.DataTypeComponent field1 = struct.getComponent(0);
            ghidra.program.model.data.DataTypeComponent field2 = struct.getComponent(1);
            ghidra.program.model.data.DataTypeComponent field3 = struct.getComponent(2);

            assertEquals("field1", field1.getFieldName());
            assertEquals("field2", field2.getFieldName());
            assertEquals("field3", field3.getFieldName());

            assertTrue("field2 should be short", field2.getDataType().getName().contains("short"));
            assertTrue("field3 should be long", field3.getDataType().getName().contains("long"));
        });
    }

    @Test
    public void testDeleteStructureWithForceParameter() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create a structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "parse");
            createArgs.put("cDefinition", "struct DeleteTestForce { int field1; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Verify structure exists
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "DeleteTestForce");
            assertNotNull("Structure should exist", dt);

            // Delete structure (no references, so should succeed even without force)
            Map<String, Object> deleteArgs = new HashMap<>();
            deleteArgs.put("programPath", program_path);
            deleteArgs.put("action", "delete");
            deleteArgs.put("structureName", "DeleteTestForce");

            CallToolResult deleteResult = client.callTool(new CallToolRequest("manage-structures", deleteArgs));
            assertMcpResultNotError(deleteResult, "Delete should succeed");

            TextContent content = (TextContent) deleteResult.content().get(0);
            JsonNode json = parseJsonContent(content.text());

            assertTrue("deleted should be true", json.get("deleted").asBoolean());
            assertEquals("Successfully deleted structure: DeleteTestForce", json.get("message").asText());

            // Verify structure was deleted
            dt = findDataTypeByName(dtm, "DeleteTestForce");
            assertNull("Structure should be deleted", dt);
        });
    }

    @Test
    public void testApplyStructure() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // First create a structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "parse");
            createArgs.put("cDefinition", "struct ApplyTest { int field1; char field2; };");

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertMcpResultNotError(createResult, "Structure creation should succeed");

            // Apply structure to an address
            Address applyAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000050);
            int txId = program.startTransaction("Create data for apply");
            try {
                try {
                    ghidra.program.model.listing.Data createdData = program.getListing().createData(applyAddr, new ghidra.program.model.data.ByteDataType(), 1);
                    if (createdData == null) {
                        fail("Failed to create data at address");
                    }
                } catch (Exception e) {
                    fail("Failed to create data: " + e.getMessage());
                }
            } finally {
                program.endTransaction(txId, true);
            }

            Map<String, Object> applyArgs = new HashMap<>();
            applyArgs.put("programPath", program_path);
            applyArgs.put("action", "apply");
            applyArgs.put("structureName", "ApplyTest");
            applyArgs.put("addressOrSymbol", applyAddr.toString());
            applyArgs.put("clearExisting", true);

            CallToolResult applyResult = client.callTool(new CallToolRequest("manage-structures", applyArgs));
            assertFalse("Apply structure should succeed", applyResult.isError());

            // Verify structure was applied
            ghidra.program.model.listing.Data data = program.getListing().getDataAt(applyAddr);
            if (data != null) {
                DataType dataType = data.getDataType();
                assertTrue("Data type should be structure", dataType instanceof Structure);
                assertEquals("Structure name should match", "ApplyTest", dataType.getName());
            }
        });
    }

    @Test
    public void testListStructuresWithFilters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create structures with different names
            Map<String, Object> createArgs1 = new HashMap<>();
            createArgs1.put("programPath", program_path);
            createArgs1.put("action", "create");
            createArgs1.put("name", "FilterTest1");
            client.callTool(new CallToolRequest("manage-structures", createArgs1));

            Map<String, Object> createArgs2 = new HashMap<>();
            createArgs2.put("programPath", program_path);
            createArgs2.put("action", "create");
            createArgs2.put("name", "FilterTest2");
            client.callTool(new CallToolRequest("manage-structures", createArgs2));

            // List with name filter
            Map<String, Object> listArgs = new HashMap<>();
            listArgs.put("programPath", program_path);
            listArgs.put("action", "list");
            listArgs.put("nameFilter", "FilterTest");
            listArgs.put("includeBuiltIn", false);

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", listArgs));
            assertFalse("List with filter should succeed", result.isError());

            TextContent content = (TextContent) result.content().get(0);
            JsonNode json = parseJsonContent(content.text());
            assertTrue("Should have structures field", json.has("structures"));
        });
    }

    @Test
    public void testStructuresValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Create structure
            Map<String, Object> createArgs = new HashMap<>();
            createArgs.put("programPath", program_path);
            createArgs.put("action", "create");
            createArgs.put("name", "StateValidationStruct");
            createArgs.put("size", 8);

            CallToolResult createResult = client.callTool(new CallToolRequest("manage-structures", createArgs));
            assertFalse("Create structure should succeed", createResult.isError());

            // Verify structure was actually created in program state
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, "StateValidationStruct");
            assertNotNull("Structure should exist in program", dt);
            assertTrue("Should be a Structure", dt instanceof Structure);
            Structure struct = (Structure) dt;
            assertEquals("Structure size should match", 8, struct.getLength());
        });
    }

    @Test
    public void testStructuresInvalidAction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("action", "invalid_action");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", arguments));

            assertTrue("Tool should have error for invalid action", result.isError());
        });
    }

    @Test
    public void testStructuresMissingRequiredParameters() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Test create without name
            Map<String, Object> arguments = new HashMap<>();
            arguments.put("programPath", program_path);
            arguments.put("action", "create");

            CallToolResult result = client.callTool(new CallToolRequest("manage-structures", arguments));

            assertTrue("Tool should have error for missing name", result.isError());

            // Test parse without c_definition
            arguments.clear();
            arguments.put("programPath", program_path);
            arguments.put("action", "parse");

            result = client.callTool(new CallToolRequest("manage-structures", arguments));

            assertTrue("Tool should have error for missing c_definition", result.isError());
        });
    }

    /**
     * Helper method to find a data type by name in all categories
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        java.util.Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
        }
        return null;
    }
}
