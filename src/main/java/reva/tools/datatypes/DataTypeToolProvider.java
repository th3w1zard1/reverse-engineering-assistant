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
package reva.tools.datatypes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.DataTypeArchiveService;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.RevaProgramManager;
import reva.tools.AbstractToolProvider;
import reva.util.DataTypeParserUtil;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for data type operations.
 * Provides tools to list data type archives and access data types.
 */
public class DataTypeToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public DataTypeToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageDataTypesTool();
    }

    private void registerManageDataTypesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of("type", "string", "description", "Path to the program in the Ghidra Project"));
        properties.put("action", Map.of(
            "type", "string",
            "description", "Action to perform: 'archives', 'list', 'by_string', 'apply'",
            "enum", List.of("archives", "list", "by_string", "apply")
        ));
        properties.put("archive_name", Map.of("type", "string", "description", "Name of the data type archive when action='list', 'by_string', or 'apply'"));
        properties.put("category_path", Map.of("type", "string", "description", "Path to category to list data types from when action='list'", "default", "/"));
        properties.put("include_subcategories", Map.of("type", "boolean", "description", "Whether to include data types from subcategories when action='list'", "default", false));
        properties.put("start_index", Map.of("type", "integer", "description", "Starting index for pagination when action='list'", "default", 0));
        properties.put("max_count", Map.of("type", "integer", "description", "Maximum number of data types to return when action='list'", "default", 100));
        properties.put("data_type_string", Map.of("type", "string", "description", "String representation of the data type when action='by_string' or 'apply'"));
        properties.put("address_or_symbol", Map.of("type", "string", "description", "Address or symbol name to apply the data type to when action='apply'"));

        List<String> required = List.of("programPath", "action");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage_data_types")
            .title("Manage Data Types")
            .description("Get data type archives, list data types, get data type by string representation, or apply data types to addresses/symbols.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                String action = getString(request, "action");
                switch (action) {
                    case "archives":
                        return handleArchivesAction(request);
                    case "list":
                        return handleListAction(request);
                    case "by_string":
                        return handleByStringAction(request);
                    case "apply":
                        return handleApplyAction(request);
                    default:
                        return createErrorResult("Invalid action: " + action);
                }
            } catch (Exception e) {
                logError("Error in manage_data_types", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleArchivesAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program targetProgram = getProgramFromArgs(request);
        List<Map<String, Object>> archivesData = new ArrayList<>();

        DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
        Map<String, Object> builtInInfo = new HashMap<>();
        builtInInfo.put("name", builtInDTM.getName());
        builtInInfo.put("type", "BUILT_IN");
        builtInInfo.put("id", builtInDTM.getUniversalID() != null ? builtInDTM.getUniversalID().getValue() : null);
        builtInInfo.put("dataTypeCount", builtInDTM.getDataTypeCount(true));
        builtInInfo.put("categoryCount", builtInDTM.getCategoryCount());
        archivesData.add(builtInInfo);

        DataTypeManager dtm = targetProgram.getDataTypeManager();
        Map<String, Object> archiveInfo = new HashMap<>();
        archiveInfo.put("name", dtm.getName());
        archiveInfo.put("type", "PROGRAM");
        archiveInfo.put("id", dtm.getUniversalID() != null ? dtm.getUniversalID().getValue() : null);
        archiveInfo.put("dataTypeCount", dtm.getDataTypeCount(true));
        archiveInfo.put("categoryCount", dtm.getCategoryCount());
        archiveInfo.put("programPath", targetProgram.getDomainFile().getPathname());
        archivesData.add(archiveInfo);

        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
        for (Program program : openPrograms) {
            if (program.getDomainFile().getPathname().equals(targetProgram.getDomainFile().getPathname())) {
                continue;
            }
            DataTypeManager programDtm = program.getDataTypeManager();
            Map<String, Object> programArchiveInfo = new HashMap<>();
            programArchiveInfo.put("name", programDtm.getName());
            programArchiveInfo.put("type", "PROGRAM");
            programArchiveInfo.put("id", programDtm.getUniversalID() != null ? programDtm.getUniversalID().getValue() : null);
            programArchiveInfo.put("dataTypeCount", programDtm.getDataTypeCount(true));
            programArchiveInfo.put("categoryCount", programDtm.getCategoryCount());
            programArchiveInfo.put("programPath", program.getDomainFile().getPathname());
            archivesData.add(programArchiveInfo);
        }

        reva.plugin.RevaPlugin plugin = RevaInternalServiceRegistry.getService(reva.plugin.RevaPlugin.class);
        if (plugin != null) {
            DataTypeArchiveService archiveService = plugin.getTool().getService(DataTypeArchiveService.class);
            if (archiveService != null) {
                DataTypeManager[] managers = archiveService.getDataTypeManagers();
                for (DataTypeManager standaloneDtm : managers) {
                    boolean isProgramDTM = false;
                    for (Program program : openPrograms) {
                        if (standaloneDtm == program.getDataTypeManager()) {
                            isProgramDTM = true;
                            break;
                        }
                    }
                    if (isProgramDTM) continue;
                    Map<String, Object> standaloneArchiveInfo = new HashMap<>();
                    standaloneArchiveInfo.put("name", standaloneDtm.getName());
                    standaloneArchiveInfo.put("type", standaloneDtm.getType().toString());
                    standaloneArchiveInfo.put("id", standaloneDtm.getUniversalID() != null ? standaloneDtm.getUniversalID().getValue() : null);
                    standaloneArchiveInfo.put("dataTypeCount", standaloneDtm.getDataTypeCount(true));
                    standaloneArchiveInfo.put("categoryCount", standaloneDtm.getCategoryCount());
                    archivesData.add(standaloneArchiveInfo);
                }
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("archives", archivesData);
        result.put("count", archivesData.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleListAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program targetProgram = getProgramFromArgs(request);
        String archiveName = getOptionalString(request, "archive_name", getOptionalString(request, "archiveName", null));
        if (archiveName == null) {
            return createErrorResult("archive_name is required for action='list'");
        }
        String categoryPath = getOptionalString(request, "category_path", getOptionalString(request, "categoryPath", "/"));
        boolean includeSubcategories = getOptionalBoolean(request, "include_subcategories", getOptionalBoolean(request, "includeSubcategories", false));
        int startIndex = getOptionalInt(request, "start_index", getOptionalInt(request, "startIndex", 0));
        int maxCount = getOptionalInt(request, "max_count", getOptionalInt(request, "maxCount", 100));

        String programPath = targetProgram.getDomainFile().getPathname();
        DataTypeManager dtm = DataTypeParserUtil.findDataTypeManager(archiveName, programPath);
        if (dtm == null) {
            return createErrorResult("Data type archive not found: " + archiveName);
        }

        Category category;
        if (categoryPath.equals("/")) {
            category = dtm.getRootCategory();
        } else {
            ghidra.program.model.data.CategoryPath path = new ghidra.program.model.data.CategoryPath(categoryPath);
            category = dtm.getCategory(path);
            if (category == null) {
                return createErrorResult("Category not found: " + categoryPath);
            }
        }

        List<DataType> dataTypes = new ArrayList<>();
        if (includeSubcategories) {
            addDataTypesRecursively(category, dataTypes);
        } else {
            for (DataType dt : category.getDataTypes()) {
                dataTypes.add(dt);
            }
        }

        int endIndex = Math.min(startIndex + maxCount, dataTypes.size());
        List<Map<String, Object>> dataTypesData = new ArrayList<>();
        if (startIndex < dataTypes.size()) {
            for (int i = startIndex; i < endIndex; i++) {
                dataTypesData.add(createDataTypeInfo(dataTypes.get(i)));
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("archiveName", archiveName);
        result.put("categoryPath", categoryPath);
        result.put("includeSubcategories", includeSubcategories);
        result.put("startIndex", startIndex);
        result.put("totalCount", dataTypes.size());
        result.put("returnedCount", dataTypesData.size());
        result.put("dataTypes", dataTypesData);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleByStringAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program targetProgram = getProgramFromArgs(request);
        String dataTypeString = getOptionalString(request, "data_type_string", getOptionalString(request, "dataTypeString", null));
        if (dataTypeString == null) {
            return createErrorResult("data_type_string is required for action='by_string'");
        }
        String archiveName = getOptionalString(request, "archive_name", getOptionalString(request, "archiveName", ""));

        String programPath = targetProgram.getDomainFile().getPathname();
        try {
            Map<String, Object> result = DataTypeParserUtil.parseDataTypeFromString(dataTypeString, archiveName, programPath);
            if (result == null) {
                return createErrorResult("Could not find or parse data type: " + dataTypeString);
            }
            return createJsonResult(result);
        } catch (Exception e) {
            return createErrorResult("Error parsing data type: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleApplyAction(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Program program = getProgramFromArgs(request);
        String dataTypeString = getOptionalString(request, "data_type_string", getOptionalString(request, "dataTypeString", null));
        if (dataTypeString == null) {
            return createErrorResult("data_type_string is required for action='apply'");
        }
        String addressOrSymbol = getOptionalString(request, "address_or_symbol", getOptionalString(request, "addressOrSymbol", null));
        if (addressOrSymbol == null) {
            return createErrorResult("address_or_symbol is required for action='apply'");
        }
        String archiveName = getOptionalString(request, "archive_name", getOptionalString(request, "archiveName", ""));

        ghidra.program.model.address.Address address = reva.util.AddressUtil.resolveAddressOrSymbol(program, addressOrSymbol);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressOrSymbol);
        }

        try {
            ghidra.program.model.data.DataType dataType = reva.util.DataTypeParserUtil.parseDataTypeObjectFromString(dataTypeString, archiveName);
            if (dataType == null) {
                return createErrorResult("Could not find data type: " + dataTypeString);
            }

            int transactionID = program.startTransaction("Apply Data Type");
            boolean success = false;
            try {
                ghidra.program.model.listing.Listing listing = program.getListing();
                if (listing.getDataAt(address) != null) {
                    listing.clearCodeUnits(address, address.add(dataType.getLength() - 1), false);
                }
                ghidra.program.model.listing.Data createdData = listing.createData(address, dataType);
                if (createdData == null) {
                    throw new Exception("Failed to create data at address: " + address);
                }
                success = true;
                autoSaveProgram(program, "Apply data type");
                Map<String, Object> resultData = new HashMap<>();
                resultData.put("success", true);
                resultData.put("address", reva.util.AddressUtil.formatAddress(address));
                resultData.put("dataType", dataType.getName());
                resultData.put("dataTypeDisplayName", dataType.getDisplayName());
                resultData.put("length", dataType.getLength());
                return createJsonResult(resultData);
            } finally {
                program.endTransaction(transactionID, success);
            }
        } catch (Exception e) {
            return createErrorResult("Error applying data type: " + e.getMessage());
        }
    }

    /**
     * Add data types recursively from a category and its subcategories
     * @param category The category to get data types from
     * @param dataTypes The list to add data types to
     */
    private void addDataTypesRecursively(Category category, List<DataType> dataTypes) {
        // Add data types from this category
        for (DataType dt : category.getDataTypes()) {
            dataTypes.add(dt);
        }

        // Add data types from subcategories
        for (Category subCategory : category.getCategories()) {
            addDataTypesRecursively(subCategory, dataTypes);
        }
    }

    /**
     * Create a map with information about a data type
     * @param dt The data type
     * @return Map with data type information
     */
    private Map<String, Object> createDataTypeInfo(DataType dt) {
        return DataTypeParserUtil.createDataTypeInfo(dt);
    }
}
