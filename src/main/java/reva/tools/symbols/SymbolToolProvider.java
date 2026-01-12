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
package reva.tools.symbols;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;
import reva.util.SymbolUtil;

/**
 * Tool provider for symbol-related operations.
 */
public class SymbolToolProvider extends AbstractToolProvider {
    /**
     * Constructor
     * @param server The MCP server
     */
    public SymbolToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageSymbolsTool();
    }

    private void registerManageSymbolsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Operation mode: 'classes', 'namespaces', 'imports', 'exports', 'create_label', 'symbols', 'count', 'rename_data'",
            "enum", List.of("classes", "namespaces", "imports", "exports", "create_label", "symbols", "count", "rename_data")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address where to create the label when mode='create_label' or address of data to rename when mode='rename_data'"));
        properties.put("label_name", SchemaUtil.stringProperty("Name for the label when mode='create_label'"));
        properties.put("new_name", SchemaUtil.stringProperty("New name for the data label when mode='rename_data'"));
        properties.put("library_filter", SchemaUtil.stringProperty("Optional library name to filter by when mode='imports' (case-insensitive)"));
        properties.put("max_results", SchemaUtil.integerPropertyWithDefault("Maximum number of imports/exports to return when mode='imports' or 'exports'", 500));
        properties.put("start_index", SchemaUtil.integerPropertyWithDefault("Starting index for pagination (0-based)", 0));
        properties.put("offset", SchemaUtil.integerPropertyWithDefault("Alternative pagination offset parameter", 0));
        properties.put("limit", SchemaUtil.integerPropertyWithDefault("Alternative pagination limit parameter", 100));
        properties.put("group_by_library", SchemaUtil.booleanPropertyWithDefault("Whether to group imports by library name when mode='imports'", true));
        properties.put("include_external", SchemaUtil.booleanPropertyWithDefault("Whether to include external symbols when mode='symbols' or 'count'", false));
        properties.put("max_count", SchemaUtil.integerPropertyWithDefault("Maximum number of symbols to return when mode='symbols'", 200));
        properties.put("filter_default_names", SchemaUtil.booleanPropertyWithDefault("Whether to filter out default Ghidra generated names", true));

        List<String> required = List.of("programPath", "mode");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-symbols")
            .title("Manage Symbols")
            .description("List classes, namespaces, imports, exports, create labels, get symbols, count symbols, or rename data labels.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String mode = getString(request, "mode");

                switch (mode) {
                    case "classes":
                        return handleClassesMode(program, request);
                    case "namespaces":
                        return handleNamespacesMode(program, request);
                    case "imports":
                        return handleImportsMode(program, request);
                    case "exports":
                        return handleExportsMode(program, request);
                    case "create_label":
                        return handleCreateLabelMode(program, request);
                    case "symbols":
                        return handleSymbolsMode(program, request);
                    case "count":
                        return handleCountMode(program, request);
                    case "rename_data":
                        return handleRenameDataMode(program, request);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: classes, namespaces, imports, exports, create_label, symbols, count, rename_data");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in manage-symbols", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }


    private McpSchema.CallToolResult handleClassesMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int startIndex = getOptionalInt(request, "start_index", getOptionalInt(request, "offset", 0));
        int limit = getOptionalInt(request, "limit", getOptionalInt(request, "max_count", 100));
        if (startIndex < 0) startIndex = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        Set<String> classNames = new HashSet<>();
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();
            if (symbol.getSymbolType() == SymbolType.CLASS) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    classNames.add(ns.getName(true));
                }
            }
        }

        List<String> sortedClasses = new ArrayList<>(classNames);
        sortedClasses.sort(String::compareToIgnoreCase);

        int endIndex = Math.min(startIndex + limit, sortedClasses.size());
        List<String> paginated = sortedClasses.subList(startIndex, endIndex);

        Map<String, Object> result = new HashMap<>();
        result.put("classes", paginated);
        result.put("startIndex", startIndex);
        result.put("limit", limit);
        result.put("totalCount", sortedClasses.size());
        result.put("hasMore", endIndex < sortedClasses.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleNamespacesMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int startIndex = getOptionalInt(request, "start_index", getOptionalInt(request, "offset", 0));
        int limit = getOptionalInt(request, "limit", getOptionalInt(request, "max_count", 100));
        if (startIndex < 0) startIndex = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        Set<String> namespaceNames = new HashSet<>();
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal() && symbol.getSymbolType() != SymbolType.CLASS) {
                namespaceNames.add(ns.getName(true));
            }
        }

        List<String> sortedNamespaces = new ArrayList<>(namespaceNames);
        sortedNamespaces.sort(String::compareToIgnoreCase);

        int endIndex = Math.min(startIndex + limit, sortedNamespaces.size());
        List<String> paginated = sortedNamespaces.subList(startIndex, endIndex);

        Map<String, Object> result = new HashMap<>();
        result.put("namespaces", paginated);
        result.put("startIndex", startIndex);
        result.put("limit", limit);
        result.put("totalCount", sortedNamespaces.size());
        result.put("hasMore", endIndex < sortedNamespaces.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleImportsMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String libraryFilter = getOptionalString(request, "library_filter", null);
        int maxResults = getOptionalInt(request, "max_results", 500);
        int startIndex = getOptionalInt(request, "start_index", getOptionalInt(request, "offset", 0));
        boolean groupByLibrary = getOptionalBoolean(request, "group_by_library", true);

        if (maxResults <= 0) maxResults = 500;
        if (maxResults > 10000) maxResults = 10000;
        if (startIndex < 0) startIndex = 0;

        List<Map<String, Object>> allImports = collectImports(program, libraryFilter);
        List<Map<String, Object>> paginated = paginate(allImports, startIndex, maxResults);

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("totalCount", allImports.size());
        result.put("startIndex", startIndex);
        result.put("returnedCount", paginated.size());

        if (groupByLibrary) {
            Map<String, List<Map<String, Object>>> grouped = groupImportsByLibrary(paginated);
            result.put("libraries", grouped);
            result.put("groupedByLibrary", grouped);
        } else {
            result.put("imports", paginated);
        }

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleExportsMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int maxResults = getOptionalInt(request, "max_results", 500);
        int startIndex = getOptionalInt(request, "start_index", getOptionalInt(request, "offset", 0));

        if (maxResults <= 0) maxResults = 500;
        if (maxResults > 10000) maxResults = 10000;
        if (startIndex < 0) startIndex = 0;

        List<Map<String, Object>> allExports = collectExports(program);
        List<Map<String, Object>> paginated = paginate(allExports, startIndex, maxResults);

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("totalCount", allExports.size());
        result.put("startIndex", startIndex);
        result.put("returnedCount", paginated.size());
        result.put("exports", paginated);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleCreateLabelMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='create_label'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        String labelName = getOptionalString(request, "label_name", null);
        if (labelName == null || labelName.trim().isEmpty()) {
            return createErrorResult("label_name is required for mode='create_label'");
        }

        int transactionID = program.startTransaction("Create Label");
        boolean success = false;

        try {
            SymbolTable symbolTable = program.getSymbolTable();
            Symbol symbol = symbolTable.createLabel(address, labelName,
                program.getGlobalNamespace(), ghidra.program.model.symbol.SourceType.USER_DEFINED);

            if (symbol == null) {
                throw new Exception("Failed to create label at address: " + AddressUtil.formatAddress(address));
            }

            success = true;

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("success", true);
            resultData.put("labelName", labelName);
            resultData.put("address", AddressUtil.formatAddress(address));
            resultData.put("isPrimary", symbol.isPrimary());

            autoSaveProgram(program, "Create label");
            return createJsonResult(resultData);
        } catch (Exception e) {
            return createErrorResult("Error creating label: " + e.getMessage());
        } finally {
            program.endTransaction(transactionID, success);
        }
    }

    private McpSchema.CallToolResult handleSymbolsMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        boolean includeExternal = getOptionalBoolean(request, "include_external",
            getOptionalBoolean(request, "includeExternal", false));

        // Handle pagination
        int startIndexValue = getOptionalInt(request, "start_index",
            getOptionalInt(request, "offset", 0));
        int maxCountValue = getOptionalInt(request, "max_count",
            getOptionalInt(request, "limit", 200));
        if (startIndexValue < 0) startIndexValue = 0;
        if (maxCountValue <= 0) maxCountValue = 200;
        if (maxCountValue > 10000) maxCountValue = 10000;
        final int startIndex = startIndexValue;
        final int maxCount = maxCountValue;

        boolean filterDefaultNames = getOptionalBoolean(request, "filter_default_names",
            getOptionalBoolean(request, "filterDefaultNames", true));

        List<Map<String, Object>> symbolData = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

        AtomicInteger currentIndex = new AtomicInteger(0);

        symbolIterator.forEach(symbol -> {
            if (!includeExternal && symbol.isExternal()) {
                return;
            }

            if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(symbol.getName())) {
                return;
            }

            int index = currentIndex.getAndIncrement();

            if (index < startIndex) {
                return;
            }

            if (symbolData.size() >= maxCount) {
                return;
            }

            symbolData.add(createSymbolInfo(symbol));
        });

        Map<String, Object> paginationInfo = new HashMap<>();
        paginationInfo.put("startIndex", startIndex);
        paginationInfo.put("requestedCount", maxCount);
        paginationInfo.put("actualCount", symbolData.size());
        paginationInfo.put("nextStartIndex", startIndex + symbolData.size());
        paginationInfo.put("totalProcessed", currentIndex.get());
        paginationInfo.put("includeExternal", includeExternal);
        paginationInfo.put("filterDefaultNames", filterDefaultNames);

        Map<String, Object> result = new HashMap<>();
        result.put("pagination", paginationInfo);
        result.put("symbols", symbolData);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleCountMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        boolean includeExternal = getOptionalBoolean(request, "include_external",
            getOptionalBoolean(request, "includeExternal", false));
        boolean filterDefaultNames = getOptionalBoolean(request, "filter_default_names",
            getOptionalBoolean(request, "filterDefaultNames", true));

        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

        AtomicInteger count = new AtomicInteger(0);
        symbolIterator.forEach(symbol -> {
            if (!includeExternal && symbol.isExternal()) {
                return;
            }

            if (!filterDefaultNames || !SymbolUtil.isDefaultSymbolName(symbol.getName())) {
                count.incrementAndGet();
            }
        });

        Map<String, Object> countData = new HashMap<>();
        countData.put("count", count.get());
        countData.put("includeExternal", includeExternal);
        countData.put("filterDefaultNames", filterDefaultNames);

        return createJsonResult(countData);
    }

    private McpSchema.CallToolResult handleRenameDataMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='rename_data'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        String newName = getOptionalString(request, "new_name", null);
        if (newName == null || newName.trim().isEmpty()) {
            return createErrorResult("new_name is required for mode='rename_data'");
        }

        int transactionID = program.startTransaction("Rename Data");
        boolean success = false;

        try {
            SymbolTable symbolTable = program.getSymbolTable();
            Symbol primarySymbol = symbolTable.getPrimarySymbol(address);

            if (primarySymbol == null) {
                // Try to get data at address
                Data data = program.getListing().getDataAt(address);
                if (data == null) {
                    return createErrorResult("No symbol or data found at address: " + AddressUtil.formatAddress(address));
                }
                // Get symbol for the data
                primarySymbol = symbolTable.getPrimarySymbol(address);
                if (primarySymbol == null) {
                    return createErrorResult("No symbol found for data at address: " + AddressUtil.formatAddress(address));
                }
            }

            String oldName = primarySymbol.getName();
            primarySymbol.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            success = true;

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("success", true);
            resultData.put("oldName", oldName);
            resultData.put("newName", newName);
            resultData.put("address", AddressUtil.formatAddress(address));

            autoSaveProgram(program, "Rename data");
            return createJsonResult(resultData);
        } catch (Exception e) {
            return createErrorResult("Error renaming data: " + e.getMessage());
        } finally {
            program.endTransaction(transactionID, success);
        }
    }

    private List<Map<String, Object>> collectImports(Program program, String libraryFilter) {
        List<Map<String, Object>> imports = new ArrayList<>();
        FunctionIterator externalFunctions = program.getFunctionManager().getExternalFunctions();

        while (externalFunctions.hasNext()) {
            Function func = externalFunctions.next();
            ExternalLocation extLoc = func.getExternalLocation();
            String library = extLoc != null ? extLoc.getLibraryName() : "<unknown>";

            if (libraryFilter != null && !libraryFilter.isEmpty() &&
                !library.toLowerCase().contains(libraryFilter.toLowerCase())) {
                continue;
            }

            Map<String, Object> info = new HashMap<>();
            info.put("name", func.getName());
            info.put("library", library);

            Address entryPoint = func.getEntryPoint();
            if (entryPoint != null) {
                info.put("address", AddressUtil.formatAddress(entryPoint));
            }

            if (extLoc != null) {
                String originalName = extLoc.getOriginalImportedName();
                if (originalName != null && !originalName.equals(func.getName())) {
                    info.put("originalName", originalName);
                    if (originalName.startsWith("Ordinal_")) {
                        try {
                            info.put("ordinal", Integer.parseInt(originalName.substring(8)));
                        } catch (NumberFormatException e) {
                            // Not a valid ordinal format
                        }
                    }
                }
            }

            if (func.getSignature() != null) {
                info.put("signature", func.getSignature().getPrototypeString());
            }

            imports.add(info);
        }

        imports.sort((a, b) -> {
            int cmp = ((String) a.get("library")).compareToIgnoreCase((String) b.get("library"));
            return cmp != 0 ? cmp : ((String) a.get("name")).compareToIgnoreCase((String) b.get("name"));
        });

        return imports;
    }

    private List<Map<String, Object>> collectExports(Program program) {
        List<Map<String, Object>> exports = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager funcManager = program.getFunctionManager();

        AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
        while (entryPoints.hasNext()) {
            Address addr = entryPoints.next();

            Map<String, Object> info = new HashMap<>();
            info.put("address", AddressUtil.formatAddress(addr));

            Symbol symbol = symbolTable.getPrimarySymbol(addr);
            if (symbol != null) {
                info.put("name", symbol.getName());
                info.put("symbolType", symbol.getSymbolType().toString());

                Function function = funcManager.getFunctionAt(addr);
                info.put("isFunction", function != null);
                if (function != null && function.getSignature() != null) {
                    info.put("signature", function.getSignature().getPrototypeString());
                }
            }

            exports.add(info);
        }

        exports.sort((a, b) -> {
            String nameA = (String) a.getOrDefault("name", "");
            String nameB = (String) b.getOrDefault("name", "");
            return nameA.compareToIgnoreCase(nameB);
        });

        return exports;
    }

    private List<Map<String, Object>> paginate(List<Map<String, Object>> list, int startIndex, int maxCount) {
        int endIndex = Math.min(startIndex + maxCount, list.size());
        if (startIndex >= list.size()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(list.subList(startIndex, endIndex));
    }

    private Map<String, List<Map<String, Object>>> groupImportsByLibrary(List<Map<String, Object>> imports) {
        Map<String, List<Map<String, Object>>> grouped = new HashMap<>();
        for (Map<String, Object> imp : imports) {
            String library = (String) imp.getOrDefault("library", "<unknown>");
            grouped.computeIfAbsent(library, k -> new ArrayList<>()).add(imp);
        }
        return grouped;
    }

    /**
     * Create a map of symbol information
     * @param symbol The symbol to extract information from
     * @return Map containing symbol properties
     */
    private Map<String, Object> createSymbolInfo(Symbol symbol) {
        Map<String, Object> symbolInfo = new HashMap<>();
        symbolInfo.put("name", symbol.getName());
        symbolInfo.put("address", AddressUtil.formatAddress(symbol.getAddress()));
        symbolInfo.put("namespace", symbol.getParentNamespace().getName());
        symbolInfo.put("id", symbol.getID());
        symbolInfo.put("symbolType", symbol.getSymbolType().toString());
        symbolInfo.put("isPrimary", symbol.isPrimary());
        symbolInfo.put("isExternal", symbol.isExternal());

        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            symbolInfo.put("isFunction", true);
        } else {
            symbolInfo.put("isFunction", false);
        }

        return symbolInfo;
    }
}
