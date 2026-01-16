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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for structure definition and manipulation operations.
 * Provides tools to create, modify, and apply structures in Ghidra programs.
 */
public class StructureToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public StructureToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageStructuresTool();
    }

    private void registerManageStructuresTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("action", Map.of(
            "type", "string",
            "description", "Action to perform: 'parse', 'validate', 'create', 'add_field', 'modify_field', 'modify_from_c', 'info', 'list', 'apply', 'delete', 'parse_header'",
            "enum", List.of("parse", "validate", "create", "add_field", "modify_field", "modify_from_c", "info", "list", "apply", "delete", "parse_header")
        ));
        properties.put("cDefinition", SchemaUtil.stringProperty("C-style structure definition when action='parse', 'validate', or 'modify_from_c'"));
        properties.put("headerContent", SchemaUtil.stringProperty("C header file content when action='parse_header'"));
        properties.put("structureName", SchemaUtil.stringProperty("Name of the structure"));
        properties.put("name", SchemaUtil.stringProperty("Name of the structure when action='create'"));
        properties.put("size", SchemaUtil.integerPropertyWithDefault("Initial size when action='create'", 0));
        properties.put("type", Map.of(
            "type", "string",
            "description", "Structure type when action='create'",
            "enum", List.of("structure", "union"),
            "default", "structure"
        ));
        properties.put("category", SchemaUtil.stringPropertyWithDefault("Category path", "/"));
        properties.put("packed", SchemaUtil.booleanPropertyWithDefault("Whether structure should be packed when action='create'", false));
        properties.put("description", SchemaUtil.stringProperty("Description of the structure when action='create'"));
        properties.put("fieldName", SchemaUtil.stringProperty("Name of the field when action='add_field' or 'modify_field'"));
        properties.put("dataType", SchemaUtil.stringProperty("Data type when action='add_field'"));
        properties.put("offset", SchemaUtil.integerProperty("Field offset when action='add_field' or 'modify_field'"));
        properties.put("comment", SchemaUtil.stringProperty("Field comment when action='add_field'"));
        properties.put("newDataType", SchemaUtil.stringProperty("New data type for the field when action='modify_field'"));
        properties.put("newFieldName", SchemaUtil.stringProperty("New name for the field when action='modify_field'"));
        properties.put("newComment", SchemaUtil.stringProperty("New comment for the field when action='modify_field'"));
        properties.put("newLength", SchemaUtil.integerProperty("New length for the field when action='modify_field'"));
        Map<String, Object> addressOrSymbolProperty = new HashMap<>();
        addressOrSymbolProperty.put("type", "string");
        addressOrSymbolProperty.put("description", "Address or symbol name to apply structure to. Can be a single string or an array of strings for batch operations when action='apply'.");
        Map<String, Object> addressOrSymbolArraySchema = new HashMap<>();
        addressOrSymbolArraySchema.put("type", "array");
        addressOrSymbolArraySchema.put("items", Map.of("type", "string"));
        addressOrSymbolArraySchema.put("description", "Array of addresses or symbol names for batch operations");
        addressOrSymbolProperty.put("oneOf", List.of(
            Map.of("type", "string"),
            addressOrSymbolArraySchema
        ));
        properties.put("addressOrSymbol", addressOrSymbolProperty);
        properties.put("clearExisting", SchemaUtil.booleanPropertyWithDefault("Clear existing data when action='apply'", true));
        properties.put("force", SchemaUtil.booleanPropertyWithDefault("Force deletion even if structure is referenced when action='delete'", false));
        properties.put("nameFilter", SchemaUtil.stringProperty("Filter by name (substring match) when action='list'"));
        properties.put("includeBuiltIn", SchemaUtil.booleanPropertyWithDefault("Include built-in types when action='list'", false));

        List<String> required = List.of("programPath", "action");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-structures")
            .title("Manage Structures")
            .description("Parse, validate, create, modify, query, list, apply, or delete structures. Also parse entire C header files.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                String action = getString(request, "action");
                switch (action) {
                    case "parse":
                        return handleParseAction(request);
                    case "validate":
                        return handleValidateAction(request);
                    case "create":
                        return handleCreateAction(request);
                    case "add_field":
                        return handleAddFieldAction(request);
                    case "modify_field":
                        return handleModifyFieldAction(request);
                    case "modify_from_c":
                        return handleModifyFromCAction(request);
                    case "info":
                        return handleInfoAction(request);
                    case "list":
                        return handleListAction(request);
                    case "apply":
                        return handleApplyAction(request);
                    case "delete":
                        return handleDeleteAction(request);
                    case "parse_header":
                        return handleParseHeaderAction(request);
                    default:
                        return createErrorResult("Invalid action: " + action);
                }
            } catch (Exception e) {
                logError("Error in manage-structures", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleParseAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String cDefinition = getOptionalString(request, "cDefinition", null);
        if (cDefinition == null) {
            return createErrorResult("cDefinition is required for action='parse'");
        }
        String category = getOptionalString(request, "category", "/");

        DataTypeManager dtm = program.getDataTypeManager();
        CParser parser = new CParser(dtm);

        int txId = program.startTransaction("Parse C Structure");
        try {
            DataType dt = parser.parse(cDefinition);
            if (dt == null) {
                throw new Exception("Failed to parse structure definition");
            }

            CategoryPath catPath = new CategoryPath(category);
            Category cat = dtm.createCategory(catPath);

            DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
            if (cat != null && resolved.getCategoryPath() != catPath) {
                resolved.setName(resolved.getName());
                cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
            }

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Parse C structure");

            Map<String, Object> result = createStructureInfo(resolved);
            result.put("message", "Successfully created structure: " + resolved.getName());
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            Msg.error(this, "Failed to parse C structure", e);
            return createErrorResult("Failed to parse: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleValidateAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String cDefinition = getOptionalString(request, "cDefinition", null);
        if (cDefinition == null) {
            return createErrorResult("cDefinition is required for action='validate'");
        }

        try {
            Program program = getProgramFromArgs(request);
            DataTypeManager dtm = program.getDataTypeManager();
            CParser parser = new CParser(dtm);
            DataType dt = parser.parse(cDefinition);

            Map<String, Object> result = new HashMap<>();
            if (dt != null) {
                result.put("valid", true);
                result.put("parsedType", dt.getName());
                result.put("type", dt.getClass().getSimpleName());
            } else {
                result.put("valid", false);
                result.put("error", "Failed to parse structure definition");
            }
            return createJsonResult(result);
        } catch (Exception e) {
            Map<String, Object> result = new HashMap<>();
            result.put("valid", false);
            result.put("error", e.getMessage());
            return createJsonResult(result);
        }
    }

    private McpSchema.CallToolResult handleCreateAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String name = getOptionalString(request, "name", null);
        if (name == null) {
            return createErrorResult("name is required for action='create'");
        }
        int size = getOptionalInt(request, "size", 0);
        String type = getOptionalString(request, "type", "structure");
        String category = getOptionalString(request, "category", "/");
        boolean packed = getOptionalBoolean(request, "packed", false);
        String description = getOptionalString(request, "description", null);

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath catPath = new CategoryPath(category);

        int txId = program.startTransaction("Create Structure");
        try {
            Category cat = dtm.createCategory(catPath);
            Composite composite;
            if ("union".equals(type)) {
                composite = new UnionDataType(catPath, name);
            } else {
                composite = new StructureDataType(catPath, name, size);
                if (packed) {
                    ((Structure) composite).setPackingEnabled(true);
                }
            }

            if (description != null && !description.trim().isEmpty()) {
                composite.setDescription(description);
            }

            DataType resolved = dtm.resolve(composite, DataTypeConflictHandler.REPLACE_HANDLER);
            if (cat != null && resolved.getCategoryPath() != catPath) {
                resolved.setName(resolved.getName());
                cat.moveDataType(resolved, DataTypeConflictHandler.REPLACE_HANDLER);
            }

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Create structure");

            Map<String, Object> result = createStructureInfo(resolved);
            result.put("message", "Successfully created structure: " + resolved.getName());
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to create structure: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleAddFieldAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='add_field'");
        }
        String fieldName = getOptionalString(request, "fieldName", null);
        if (fieldName == null) {
            return createErrorResult("fieldName is required for action='add_field'");
        }
        String dataTypeStr = getOptionalString(request, "dataType", null);
        if (dataTypeStr == null) {
            return createErrorResult("dataType is required for action='add_field'");
        }
        Integer offset = getOptionalInteger(request.arguments(), "offset", null);
        String comment = getOptionalString(request, "comment", null);

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = dtm.getDataType(structureName);
        if (dt == null) {
            dt = findDataTypeByName(dtm, structureName);
        }
        if (dt == null) {
            return createErrorResult("Structure not found: " + structureName);
        }
        if (!(dt instanceof Composite)) {
            return createErrorResult("Data type is not a structure or union: " + structureName);
        }

        Composite composite = (Composite) dt;
        if (!(composite instanceof Structure)) {
            return createErrorResult("add_field is only supported for structures, not unions");
        }
        Structure struct = (Structure) composite;

        DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
        DataType fieldType;
        try {
            fieldType = parser.parse(dataTypeStr);
        } catch (Exception e) {
            return createErrorResult("Failed to parse data type: " + e.getMessage());
        }
        if (fieldType == null) {
            return createErrorResult("Could not parse data type: " + dataTypeStr);
        }

        int txId = program.startTransaction("Add Structure Field");
        try {
            DataTypeComponent component;
            if (offset != null) {
                component = struct.insertAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
            } else {
                component = struct.add(fieldType, fieldName, comment);
            }
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Add structure field");

            Map<String, Object> result = createStructureInfo(struct);
            result.put("message", "Successfully added field: " + fieldName);
            result.put("fieldOrdinal", component.getOrdinal());
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to add field: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleModifyFieldAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='modify_field'");
        }
        String fieldName = getOptionalString(request, "fieldName", null);
        String newDataTypeStr = getOptionalString(request, "newDataType", null);
        String newFieldName = getOptionalString(request, "newFieldName", null);
        String newComment = getOptionalString(request, "newComment", null);
        Integer newLength = getOptionalInteger(request.arguments(), "newLength", null);

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Structure)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        Structure struct = (Structure) dt;
        int txId = program.startTransaction("Modify Structure Field");
        try {
            DataTypeComponent targetComponent = null;
            int targetOrdinal = -1;

            if (fieldName != null) {
                for (int i = 0; i < struct.getNumComponents(); i++) {
                    DataTypeComponent comp = struct.getComponent(i);
                    if (fieldName.equals(comp.getFieldName())) {
                        targetComponent = comp;
                        targetOrdinal = i;
                        break;
                    }
                }
            } else {
                // If no fieldName provided, must use offset to identify field
                Integer offset = getOptionalInteger(request.arguments(), "offset", null);
                if (offset != null) {
                    targetComponent = struct.getComponentAt(offset);
                    if (targetComponent != null) {
                        targetOrdinal = targetComponent.getOrdinal();
                    }
                }
            }

            if (targetComponent == null) {
                return createErrorResult("Field not found: " + (fieldName != null ? fieldName : "at specified offset"));
            }

            // Collect replacement values
            DataType replacementType = targetComponent.getDataType();
            String replacementName = targetComponent.getFieldName();
            String replacementComment = targetComponent.getComment();
            int replacementLength = targetComponent.getLength();

            if (newDataTypeStr != null) {
                DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
                DataType newType = parser.parse(newDataTypeStr);
                if (newType == null) {
                    return createErrorResult("Failed to parse new data type: " + newDataTypeStr);
                }
                replacementType = newType;
                if (newLength == null) {
                    replacementLength = newType.getLength();
                }
            }
            if (newFieldName != null) {
                replacementName = newFieldName;
            }
            if (newComment != null) {
                replacementComment = newComment;
            }
            if (newLength != null) {
                replacementLength = newLength;
            }

            // Replace the component
            struct.replace(targetOrdinal, replacementType, replacementLength, replacementName, replacementComment);

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Modify structure field");

            Map<String, Object> result = createStructureInfo(struct);
            result.put("message", "Successfully modified field");
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to modify field: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleModifyFromCAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String cDefinition = getOptionalString(request, "cDefinition", null);
        if (cDefinition == null) {
            return createErrorResult("cDefinition is required for action='modify_from_c'");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType parsedDt;
        try {
            CParser parser = new CParser(dtm);
            parsedDt = parser.parse(cDefinition);
        } catch (Exception e) {
            return createErrorResult("Failed to parse C definition: " + e.getMessage());
        }

        if (parsedDt == null || !(parsedDt instanceof Structure)) {
            return createErrorResult("Parsed definition is not a structure");
        }

        Structure parsedStruct = (Structure) parsedDt;
        String structureName = parsedStruct.getName();
        DataType existingDt = findDataTypeByName(dtm, structureName);
        if (existingDt == null || !(existingDt instanceof Structure)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        Structure existingStruct = (Structure) existingDt;
        int txId = program.startTransaction("Modify Structure from C");
        try {
            existingStruct.deleteAll();
            for (DataTypeComponent comp : parsedStruct.getComponents()) {
                existingStruct.add(comp.getDataType(), comp.getLength(), comp.getFieldName(), comp.getComment());
            }
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Modify structure from C");

            Map<String, Object> result = createStructureInfo(existingStruct);
            result.put("message", "Successfully modified structure from C definition: " + existingStruct.getName());
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to modify structure: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleInfoAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='info'");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Composite)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        Map<String, Object> result = createDetailedStructureInfo((Composite) dt);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleListAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String nameFilter = getOptionalString(request, "nameFilter", null);
        boolean includeBuiltIn = getOptionalBoolean(request, "includeBuiltIn", false);

        DataTypeManager dtm = program.getDataTypeManager();
        List<Map<String, Object>> structures = new ArrayList<>();

        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (!(dt instanceof Composite)) continue;
            if (!includeBuiltIn && dt.getCategoryPath().toString().startsWith("/")) {
                if (dt.getCategoryPath().getName().equals("BuiltInTypes")) continue;
            }
            if (nameFilter != null && !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }
            structures.add(createStructureInfo(dt));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("structures", structures);
        result.put("count", structures.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleApplyAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='apply'");
        }
        boolean clearExisting = getOptionalBoolean(request, "clearExisting", true);

        // Check if addressOrSymbol is an array (batch mode) - supports both camelCase and snake_case via getParameterValue
        List<Object> addressOrSymbolList = getParameterAsList(request.arguments(), "addressOrSymbol");

        if (addressOrSymbolList.size() > 1 || (!addressOrSymbolList.isEmpty() && addressOrSymbolList.get(0) instanceof List)) {
            List<?> batchList = addressOrSymbolList.size() > 1 ? addressOrSymbolList : (List<?>) addressOrSymbolList.get(0);
            return handleBatchApplyStructure(program, request, structureName, clearExisting, batchList);
        }

        // Single address mode
        String addressOrSymbol = getOptionalString(request, "addressOrSymbol", null);
        if (addressOrSymbol == null) {
            return createErrorResult("addressOrSymbol is required for action='apply'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressOrSymbol);
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Composite)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        int txId = program.startTransaction("Apply Structure");
        try {
            Listing listing = program.getListing();
            if (clearExisting) {
                listing.clearCodeUnits(address, address.add(dt.getLength() - 1), false);
            }
            listing.createData(address, dt);
            program.endTransaction(txId, true);
            autoSaveProgram(program, "Apply structure");

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("structureName", structureName);
            result.put("address", AddressUtil.formatAddress(address));
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to apply structure: " + e.getMessage());
        }
    }

    /**
     * Handle batch apply structure operations when address_or_symbol is an array
     */
    private McpSchema.CallToolResult handleBatchApplyStructure(Program program, CallToolRequest request,
            String structureName, boolean clearExisting, List<?> addressList) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        // Find structure once for all addresses
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null || !(dt instanceof Composite)) {
            return createErrorResult("Structure not found: " + structureName);
        }

        int txId = program.startTransaction("Batch Apply Structure");
        boolean committed = false;

        try {
            Listing listing = program.getListing();

            for (int i = 0; i < addressList.size(); i++) {
                try {
                    String addressOrSymbol = addressList.get(i).toString();
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol);

                    if (address == null) {
                        errors.add(Map.of("index", i, "addressOrSymbol", addressOrSymbol, "error", "Could not resolve address or symbol"));
                        continue;
                    }

                    // Clear existing data if requested
                    if (clearExisting) {
                        listing.clearCodeUnits(address, address.add(dt.getLength() - 1), false);
                    }

                    // Create data with the structure type
                    listing.createData(address, dt);

                    Map<String, Object> result = new HashMap<>();
                    result.put("index", i);
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("structureName", structureName);
                    results.add(result);

                } catch (Exception e) {
                    errors.add(Map.of("index", i, "addressOrSymbol", addressList.get(i).toString(), "error", e.getMessage()));
                }
            }

            program.endTransaction(txId, true);
            committed = true;
            autoSaveProgram(program, "Batch apply structure");

        } catch (Exception e) {
            if (!committed) {
                program.endTransaction(txId, false);
            }
            return createErrorResult("Error in batch apply structure: " + e.getMessage());
        }

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("success", true);
        resultData.put("structureName", structureName);
        resultData.put("total", addressList.size());
        resultData.put("succeeded", results.size());
        resultData.put("failed", errors.size());
        resultData.put("results", results);
        if (!errors.isEmpty()) {
            resultData.put("errors", errors);
        }

        return createJsonResult(resultData);
    }

    private McpSchema.CallToolResult handleDeleteAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String structureName = getOptionalString(request, "structureName", null);
        if (structureName == null) {
            return createErrorResult("structureName is required for action='delete'");
        }
        boolean force = getOptionalBoolean(request, "force", false);

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByName(dtm, structureName);
        if (dt == null) {
            return createErrorResult("Structure not found: " + structureName);
        }

        // Check for references manually (DataTypeManager doesn't have getReferenceCount)
        if (!force) {
            // Check function signatures and variables
            List<String> functionReferences = new ArrayList<>();
            ghidra.program.model.listing.FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                ghidra.program.model.listing.Function func = functions.next();
                if (func.getReturnType().isEquivalent(dt)) {
                    functionReferences.add(func.getName() + " (return type)");
                }
                for (ghidra.program.model.listing.Parameter param : func.getParameters()) {
                    if (param.getDataType().isEquivalent(dt)) {
                        functionReferences.add(func.getName() + " (parameter: " + param.getName() + ")");
                    }
                }
                for (ghidra.program.model.listing.Variable var : func.getAllVariables()) {
                    if (var.getDataType().isEquivalent(dt)) {
                        functionReferences.add(func.getName() + " (variable: " + var.getName() + ")");
                    }
                }
            }

            // Check memory instances
            List<String> memoryReferences = new ArrayList<>();
            Listing listing = program.getListing();
            ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.getDataType().isEquivalent(dt)) {
                    memoryReferences.add(AddressUtil.formatAddress(data.getAddress()));
                }
            }

            int totalReferences = functionReferences.size() + memoryReferences.size();
            if (totalReferences > 0) {
                Map<String, Object> result = new HashMap<>();
                result.put("deleted", false);
                result.put("error", "Structure is referenced. Use force=true to delete anyway.");
                result.put("referenceCount", totalReferences);
                Map<String, Object> refs = new HashMap<>();
                refs.put("functions", functionReferences);
                refs.put("memoryLocations", memoryReferences);
                result.put("references", refs);
                return createJsonResult(result);
            }
        }

        int txId = program.startTransaction("Delete Structure");
        try {
            boolean removed = dtm.remove(dt);
            if (!removed) {
                program.endTransaction(txId, false);
                return createErrorResult("Failed to delete structure (may be locked or in use by another process)");
            }

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Delete structure");

            Map<String, Object> result = new HashMap<>();
            result.put("deleted", true);
            result.put("message", "Successfully deleted structure: " + structureName);
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to delete structure: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleParseHeaderAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String headerContent = getOptionalString(request, "headerContent", null);
        if (headerContent == null) {
            return createErrorResult("headerContent is required for action='parse_header'");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        CParser parser = new CParser(dtm);
        List<Map<String, Object>> createdTypes = new ArrayList<>();

        int txId = program.startTransaction("Parse C Header");
        try {
            String[] lines = headerContent.split("\n");
            StringBuilder currentDefinition = new StringBuilder();
            for (String line : lines) {
                currentDefinition.append(line).append("\n");
                if (line.trim().endsWith("}") || line.trim().endsWith("};")) {
                    try {
                        DataType dt = parser.parse(currentDefinition.toString());
                        if (dt != null) {
                            DataType resolved = dtm.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                            createdTypes.add(createStructureInfo(resolved));
                        }
                    } catch (Exception e) {
                        // Skip failed parse, continue with next
                    }
                    currentDefinition = new StringBuilder();
                }
            }

            program.endTransaction(txId, true);
            autoSaveProgram(program, "Parse C header");

            Map<String, Object> result = new HashMap<>();
            result.put("createdTypes", createdTypes);
            result.put("count", createdTypes.size());
            return createJsonResult(result);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to parse header: " + e.getMessage());
        }
    }

    /**
     * Helper method to find a data type by name in all categories
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        // First try direct lookup
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }

        // Search all categories
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equals(name)) {
                return dataType;
            }
        }

        return null;
    }

    /**
     * Create basic structure info map
     */
    private Map<String, Object> createStructureInfo(DataType dt) {
        Map<String, Object> info = DataTypeParserUtil.createDataTypeInfo(dt);

        if (dt instanceof Composite) {
            Composite composite = (Composite) dt;
            info.put("isUnion", dt instanceof Union);
            info.put("numComponents", composite.getNumComponents());

            if (dt instanceof Structure) {
                Structure struct = (Structure) dt;
                info.put("isPacked", struct.isPackingEnabled());
                // hasFlexibleArray check would go here if method exists
            }
        }

        return info;
    }

    /**
     * Create detailed structure info including all fields
     */
    private Map<String, Object> createDetailedStructureInfo(Composite composite) {
        Map<String, Object> info = createStructureInfo(composite);

        // Add field information with undefined byte condensing
        List<Map<String, Object>> fields = new ArrayList<>();

        int i = 0;
        while (i < composite.getNumComponents()) {
            DataTypeComponent comp = composite.getComponent(i);

            // Check if this is an undefined byte that should be condensed
            if (isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int startOrdinal = comp.getOrdinal();
                int totalLength = 0;
                int count = 0;

                while (i < composite.getNumComponents()) {
                    DataTypeComponent nextComp = composite.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Create a condensed entry for the undefined range
                Map<String, Object> fieldInfo = new HashMap<>();
                fieldInfo.put("ordinal", startOrdinal);
                fieldInfo.put("offset", startOffset);
                fieldInfo.put("length", totalLength);
                fieldInfo.put("fieldName", "<undefined>");
                fieldInfo.put("dataType", "undefined");
                fieldInfo.put("dataTypeSize", totalLength);
                fieldInfo.put("isBitfield", false);
                fieldInfo.put("isCondensed", true);
                fieldInfo.put("componentCount", count);

                fields.add(fieldInfo);
            } else {
                // Regular field - add as-is
                Map<String, Object> fieldInfo = new HashMap<>();

                fieldInfo.put("ordinal", comp.getOrdinal());
                fieldInfo.put("offset", comp.getOffset());
                fieldInfo.put("length", comp.getLength());
                fieldInfo.put("fieldName", comp.getFieldName());
                if (comp.getComment() != null && !comp.getComment().isEmpty()) {
                    fieldInfo.put("comment", comp.getComment());
                }

                DataType fieldType = comp.getDataType();
                fieldInfo.put("dataType", fieldType.getDisplayName());
                fieldInfo.put("dataTypeSize", fieldType.getLength());

                // Check if it's a bitfield
                if (comp.isBitFieldComponent()) {
                    BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                    fieldInfo.put("isBitfield", true);
                    fieldInfo.put("bitSize", bitfield.getBitSize());
                    fieldInfo.put("bitOffset", bitfield.getBitOffset());
                    fieldInfo.put("baseDataType", bitfield.getBaseDataType().getDisplayName());
                } else {
                    fieldInfo.put("isBitfield", false);
                }

                fieldInfo.put("isCondensed", false);

                fields.add(fieldInfo);
                i++;
            }
        }

        info.put("fields", fields);

        // Add C representation
        if (composite instanceof Structure) {
            info.put("cRepresentation", generateCRepresentation((Structure) composite));
        }

        return info;
    }

    /**
     * Check if a field is an undefined/default field that should be condensed
     */
    private boolean isUndefinedField(DataTypeComponent comp) {
        // Check if the field name is null or empty (undefined)
        String fieldName = comp.getFieldName();
        if (fieldName == null || fieldName.isEmpty()) {
            return true;
        }

        // Check if it's a Ghidra default field name like "field_0x0", "field_0x1", etc.
        // These are generated for undefined structure areas
        if (fieldName.startsWith("field_0x") || fieldName.startsWith("field0x")) {
            return true;
        }

        // Check if the datatype is "undefined" or "undefined1"
        DataType fieldType = comp.getDataType();
        String typeName = fieldType.getName();
        if (typeName != null && typeName.startsWith("undefined")) {
            return true;
        }

        return false;
    }

    /**
     * Generate C representation of a structure with undefined byte condensing
     */
    private String generateCRepresentation(Structure struct) {
        StringBuilder sb = new StringBuilder();
        sb.append("struct ").append(struct.getName()).append(" {\n");

        int i = 0;
        while (i < struct.getNumComponents()) {
            DataTypeComponent comp = struct.getComponent(i);
            sb.append("    ");

            // Check if this is an undefined field that should be condensed
            if (isUndefinedField(comp)) {
                // Count consecutive undefined bytes
                int startOffset = comp.getOffset();
                int totalLength = 0;
                int count = 0;

                while (i < struct.getNumComponents()) {
                    DataTypeComponent nextComp = struct.getComponent(i);
                    if (!isUndefinedField(nextComp)) {
                        break;
                    }
                    totalLength += nextComp.getLength();
                    count++;
                    i++;
                }

                // Generate condensed line with offset range comment
                sb.append("undefined reserved_0x");
                sb.append(String.format("%x", startOffset));
                sb.append("[").append(count).append("]");
                sb.append(";");
                sb.append(" // 0x");
                sb.append(String.format("%x", startOffset));
                sb.append("-0x");
                sb.append(String.format("%x", startOffset + totalLength - 1));
                sb.append("\n");
            } else {
                // Regular field - output as-is
                DataType fieldType = comp.getDataType();
                if (comp.isBitFieldComponent()) {
                    BitFieldDataType bitfield = (BitFieldDataType) fieldType;
                    sb.append(bitfield.getBaseDataType().getDisplayName());
                    sb.append(" ").append(comp.getFieldName());
                    sb.append(" : ").append(bitfield.getBitSize());
                } else {
                    sb.append(fieldType.getDisplayName());
                    sb.append(" ").append(comp.getFieldName());
                }

                sb.append(";");

                if (comp.getComment() != null) {
                    sb.append(" // ").append(comp.getComment());
                }

                sb.append("\n");
                i++;
            }
        }

        sb.append("};");
        return sb.toString();
    }

}
