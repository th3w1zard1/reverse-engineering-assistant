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
import ghidra.app.util.demangler.Demangler;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.demangler.DemangledObject;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.tools.imports.ImportExportToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;
import reva.util.SymbolUtil;

/**
 * Tool provider for symbol-related operations.
 *
 * NOTE: For imports/exports collection, this provider delegates to ImportExportToolProvider
 * methods to benefit from upstream updates to disabled tool handlers.
 */
public class SymbolToolProvider extends AbstractToolProvider {
    // Helper instance to access ImportExportToolProvider methods
    // This allows us to reuse logic from disabled tools and benefit from upstream updates
    private final ImportExportToolProvider importExportHelper;

    /**
     * Constructor
     * @param server The MCP server
     */
    public SymbolToolProvider(McpSyncServer server) {
        super(server);
        // Create helper instance to access protected methods from disabled tool provider
        this.importExportHelper = new ImportExportToolProvider(server);
    }

    @Override
    public void registerTools() {
        registerManageSymbolsTool();
    }

    private void registerManageSymbolsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser."));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Operation mode: 'classes', 'namespaces', 'imports', 'exports', 'create_label', 'symbols', 'count', 'rename_data', 'demangle'",
            "enum", List.of("classes", "namespaces", "imports", "exports", "create_label", "symbols", "count", "rename_data", "demangle")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address(es) where to create label(s) when mode='create_label' or address(es) of data to rename when mode='rename_data'. Can be a single address string or an array of address strings for batch operations."));
        properties.put("label_name", SchemaUtil.stringProperty("Name(s) for the label(s) when mode='create_label'. Can be a single string or an array of strings matching the address array."));
        properties.put("new_name", SchemaUtil.stringProperty("New name(s) for the data label(s) when mode='rename_data'. Can be a single string or an array of strings matching the address array."));
        properties.put("library_filter", SchemaUtil.stringProperty("Optional library name to filter by when mode='imports' (case-insensitive)"));
        properties.put("max_results", SchemaUtil.integerPropertyWithDefault("Maximum number of imports/exports to return when mode='imports' or 'exports'", 500));
        properties.put("start_index", SchemaUtil.integerPropertyWithDefault("Starting index for pagination (0-based)", 0));
        properties.put("offset", SchemaUtil.integerPropertyWithDefault("Alternative pagination offset parameter", 0));
        properties.put("limit", SchemaUtil.integerPropertyWithDefault("Alternative pagination limit parameter", 100));
        properties.put("group_by_library", SchemaUtil.booleanPropertyWithDefault("Whether to group imports by library name when mode='imports'", true));
        properties.put("include_external", SchemaUtil.booleanPropertyWithDefault("Whether to include external symbols when mode='symbols' or 'count'", false));
        properties.put("max_count", SchemaUtil.integerPropertyWithDefault("Maximum number of symbols to return when mode='symbols'", 200));
        properties.put("filter_default_names", SchemaUtil.booleanPropertyWithDefault("Whether to filter out default Ghidra generated names", true));
        properties.put("demangle_all", SchemaUtil.booleanPropertyWithDefault("For demangle: Demangle all symbols in program (default: false, demangle single symbol)", false));

        List<String> required = List.of("mode");

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
                    case "demangle":
                        return handleDemangleMode(program, request);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: classes, namespaces, imports, exports, create_label, symbols, count, rename_data, demangle");
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

        // Delegate to ImportExportToolProvider to benefit from upstream updates
        List<Map<String, Object>> allImports = importExportHelper.collectImports(program, libraryFilter);
        List<Map<String, Object>> paginated = importExportHelper.paginate(allImports, startIndex, maxResults);

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("totalCount", allImports.size());
        result.put("startIndex", startIndex);
        result.put("returnedCount", paginated.size());

        if (groupByLibrary) {
            // Delegate to ImportExportToolProvider to benefit from upstream updates
            List<Map<String, Object>> grouped = importExportHelper.groupImportsByLibrary(paginated);
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

        // Delegate to ImportExportToolProvider to benefit from upstream updates
        List<Map<String, Object>> allExports = importExportHelper.collectExports(program);
        List<Map<String, Object>> paginated = importExportHelper.paginate(allExports, startIndex, maxResults);

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("totalCount", allExports.size());
        result.put("startIndex", startIndex);
        result.put("returnedCount", paginated.size());
        result.put("exports", paginated);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleCreateLabelMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        // Check if address is an array (batch mode)
        Object addressValue = request.arguments().get("address");
        if (addressValue instanceof List) {
            return handleBatchCreateLabels(program, request, (List<?>) addressValue);
        }

        // Single label mode
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='create_label'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        boolean autoLabel = reva.util.EnvConfigUtil.getBooleanDefault("auto_label", true);
        String labelName = getOptionalString(request, "label_name", null);

        // Auto-label if not provided (controlled by environment variable)
        if ((labelName == null || labelName.trim().isEmpty()) && autoLabel) {
            labelName = autoLabelSymbol(program, address);
        }

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

    private McpSchema.CallToolResult handleBatchCreateLabels(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request, List<?> addressList) {
        Object labelNameValue = request.arguments().get("label_name");
        if (labelNameValue == null) {
            labelNameValue = request.arguments().get("labelName");
        }
        List<?> labelNameList = (labelNameValue instanceof List) ? (List<?>) labelNameValue : null;

        boolean autoLabel = reva.util.EnvConfigUtil.getBooleanDefault("auto_label", true);

        int txId = program.startTransaction("Batch create labels");
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        try {
            SymbolTable symbolTable = program.getSymbolTable();
            for (int i = 0; i < addressList.size(); i++) {
                try {
                    String addressStr = addressList.get(i).toString();
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                    if (address == null) {
                        errors.add(Map.of("index", i, "address", addressStr, "error", "Could not resolve address or symbol"));
                        continue;
                    }

                    String labelName = null;
                    if (labelNameList != null && i < labelNameList.size()) {
                        labelName = labelNameList.get(i).toString();
                    }

                    // Auto-label if not provided (controlled by environment variable)
                    if ((labelName == null || labelName.trim().isEmpty()) && autoLabel) {
                        labelName = autoLabelSymbol(program, address);
                    }

                    if (labelName == null || labelName.trim().isEmpty()) {
                        errors.add(Map.of("index", i, "address", addressStr, "error", "No label name provided and auto-labeling failed"));
                        continue;
                    }

                    Symbol symbol = symbolTable.createLabel(address, labelName,
                        program.getGlobalNamespace(), ghidra.program.model.symbol.SourceType.USER_DEFINED);

                    if (symbol == null) {
                        errors.add(Map.of("index", i, "address", addressStr, "error", "Failed to create label"));
                        continue;
                    }

                    results.add(Map.of(
                        "index", i,
                        "address", AddressUtil.formatAddress(address),
                        "labelName", labelName,
                        "isPrimary", symbol.isPrimary(),
                        "success", true
                    ));
                } catch (Exception e) {
                    errors.add(Map.of("index", i, "address", addressList.get(i).toString(), "error", e.getMessage()));
                }
            }

            autoSaveProgram(program, "Batch created " + results.size() + " labels");
            return createJsonResult(Map.of(
                "success", true,
                "created", results.size(),
                "failed", errors.size(),
                "results", results,
                "errors", errors.isEmpty() ? List.of() : errors
            ));
        } finally {
            program.endTransaction(txId, true);
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
        // Check if address is an array (batch mode)
        Object addressValue = request.arguments().get("address");
        if (addressValue instanceof List) {
            return handleBatchRenameData(program, request, (List<?>) addressValue);
        }

        // Single rename mode
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='rename_data'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        boolean autoLabel = reva.util.EnvConfigUtil.getBooleanDefault("auto_label", true);
        String newName = getOptionalString(request, "new_name", null);

        // Auto-label if not provided (controlled by environment variable)
        if ((newName == null || newName.trim().isEmpty()) && autoLabel) {
            newName = autoLabelSymbol(program, address);
        }

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

    private McpSchema.CallToolResult handleBatchRenameData(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request, List<?> addressList) {
        Object newNameValue = request.arguments().get("new_name");
        if (newNameValue == null) {
            newNameValue = request.arguments().get("newName");
        }
        List<?> newNameList = (newNameValue instanceof List) ? (List<?>) newNameValue : null;

        boolean autoLabel = reva.util.EnvConfigUtil.getBooleanDefault("auto_label", true);

        int txId = program.startTransaction("Batch rename data");
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        try {
            SymbolTable symbolTable = program.getSymbolTable();
            for (int i = 0; i < addressList.size(); i++) {
                try {
                    String addressStr = addressList.get(i).toString();
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                    if (address == null) {
                        errors.add(Map.of("index", i, "address", addressStr, "error", "Could not resolve address or symbol"));
                        continue;
                    }

                    Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
                    if (primarySymbol == null) {
                        Data data = program.getListing().getDataAt(address);
                        if (data == null) {
                            errors.add(Map.of("index", i, "address", addressStr, "error", "No symbol or data found"));
                            continue;
                        }
                        primarySymbol = symbolTable.getPrimarySymbol(address);
                        if (primarySymbol == null) {
                            errors.add(Map.of("index", i, "address", addressStr, "error", "No symbol found"));
                            continue;
                        }
                    }

                    String newName = null;
                    if (newNameList != null && i < newNameList.size()) {
                        newName = newNameList.get(i).toString();
                    }

                    // Auto-label if not provided (controlled by environment variable)
                    if ((newName == null || newName.trim().isEmpty()) && autoLabel) {
                        newName = autoLabelSymbol(program, address);
                    }

                    if (newName == null || newName.trim().isEmpty()) {
                        errors.add(Map.of("index", i, "address", addressStr, "error", "No name provided and auto-labeling failed"));
                        continue;
                    }

                    String oldName = primarySymbol.getName();
                    primarySymbol.setName(newName, ghidra.program.model.symbol.SourceType.USER_DEFINED);

                    results.add(Map.of(
                        "index", i,
                        "address", AddressUtil.formatAddress(address),
                        "oldName", oldName,
                        "newName", newName,
                        "success", true
                    ));
                } catch (Exception e) {
                    errors.add(Map.of("index", i, "address", addressList.get(i).toString(), "error", e.getMessage()));
                }
            }

            autoSaveProgram(program, "Batch renamed " + results.size() + " symbols");
            return createJsonResult(Map.of(
                "success", true,
                "renamed", results.size(),
                "failed", errors.size(),
                "results", results,
                "errors", errors.isEmpty() ? List.of() : errors
            ));
        } finally {
            program.endTransaction(txId, true);
        }
    }

    // REMOVED: collectImports and collectExports methods
    // These methods have been removed in favor of delegating to ImportExportToolProvider
    // to benefit from upstream updates to disabled tool handlers.
    // See importExportHelper.collectImports() and importExportHelper.collectExports()

    // REMOVED: paginate and groupImportsByLibrary methods
    // These methods have been removed in favor of delegating to ImportExportToolProvider
    // to benefit from upstream updates to disabled tool handlers.
    // See importExportHelper.paginate() and importExportHelper.groupImportsByLibrary()

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


    private McpSchema.CallToolResult handleDemangleMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        boolean demangleAll = getOptionalBoolean(request, "demangle_all", false);
        String addressStr = getOptionalString(request, "address", null);

        if (!demangleAll && addressStr == null) {
            return createErrorResult("address is required for mode='demangle' when demangle_all=false");
        }

        SymbolTable symbolTable = program.getSymbolTable();
        List<Map<String, Object>> results = new ArrayList<>();

        int txId = program.startTransaction("Demangle symbols");
        try {
            if (demangleAll) {
                SymbolIterator symbols = symbolTable.getAllSymbols(false);
                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    if (symbol.getSource() == ghidra.program.model.symbol.SourceType.IMPORTED) {
                        String mangled = symbol.getName();
                        String demangled = demangleSymbol(program, mangled);
                        if (demangled != null && !demangled.equals(mangled)) {
                            symbol.setName(demangled, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                            results.add(Map.of(
                                "address", AddressUtil.formatAddress(symbol.getAddress()),
                                "mangled", mangled,
                                "demangled", demangled
                            ));
                        }
                    }
                }
            } else {
                Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                if (address == null) {
                    return createErrorResult("Could not resolve address: " + addressStr);
                }

                Symbol symbol = symbolTable.getPrimarySymbol(address);
                if (symbol == null) {
                    return createErrorResult("No symbol found at address: " + AddressUtil.formatAddress(address));
                }

                String mangled = symbol.getName();
                String demangled = demangleSymbol(program, mangled);
                if (demangled != null && !demangled.equals(mangled)) {
                    symbol.setName(demangled, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                    results.add(Map.of(
                        "address", AddressUtil.formatAddress(address),
                        "mangled", mangled,
                        "demangled", demangled
                    ));
                } else {
                    return createJsonResult(Map.of(
                        "success", false,
                        "message", "Symbol is not mangled or could not be demangled",
                        "symbol", mangled
                    ));
                }
            }

            autoSaveProgram(program, "Demangled " + results.size() + " symbols");
            return createJsonResult(Map.of(
                "success", true,
                "demangled", results.size(),
                "results", results
            ));
        } catch (Exception e) {
            return createErrorResult("Demangle failed: " + e.getMessage());
        } finally {
            program.endTransaction(txId, true);
        }
    }

    /**
     * Automatically label a symbol based on address context (controlled by REVA_AUTO_LABEL environment variable)
     */
    private String autoLabelSymbol(Program program, Address address) {
        // Check if it's a function
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function != null) {
            List<Map<String, Object>> suggestions = reva.util.SmartSuggestionsUtil.suggestFunctionNames(program, function);
            if (!suggestions.isEmpty()) {
                return (String) suggestions.get(0).get("name");
            }
        }

        // Check for data/string at address
        Data data = program.getListing().getDataAt(address);
        if (data != null && data.hasStringValue()) {
            String str = data.getDefaultValueRepresentation();
            if (str != null && str.length() > 0 && str.length() < 50) {
                return "str_" + str.replaceAll("[^a-zA-Z0-9_]", "_").substring(0, Math.min(30, str.length()));
            }
        }

        // Default: use address-based name
        return "label_" + AddressUtil.formatAddress(address).replace("0x", "");
    }


    private Function resolveFunction(Program program, String identifier) {
        Address address = AddressUtil.resolveAddressOrSymbol(program, identifier);
        if (address != null) {
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function != null) {
                return function;
            }
        }

        FunctionManager functionManager = program.getFunctionManager();
        ghidra.program.model.listing.FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext()) {
            Function f = functions.next();
            if (f.getName().equals(identifier) || f.getName().equalsIgnoreCase(identifier)) {
                return f;
            }
        }

        return null;
    }

    /**
     * Demangle a symbol name using Ghidra's demangler service
     */
    private String demangleSymbol(Program program, String mangledName) {
        try {
            // Use DemanglerUtil.demangle() static method
            DemangledObject demangled = DemanglerUtil.demangle(program, mangledName);
            if (demangled != null) {
                return demangled.getSignature();
            }
        } catch (Exception e) {
            // Demangling failed - symbol may not be mangled or unsupported format
        }
        return null;
    }
}
