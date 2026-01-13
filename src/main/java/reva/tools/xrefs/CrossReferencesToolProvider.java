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
package reva.tools.xrefs;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.tools.imports.ImportExportToolProvider;
import reva.util.AddressUtil;
import reva.util.DecompilationContextUtil;
import reva.util.DecompilationReadTracker;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for cross-reference operations. Provides a unified tool to
 * retrieve references to and from addresses or symbols with optional
 * decompilation context snippets.
 *
 * NOTE: For thunk chain resolution, this provider delegates to
 * ImportExportToolProvider to benefit from upstream updates to disabled tool
 * handlers.
 */
public class CrossReferencesToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_TIMEOUT_SECONDS = 60;

    // Helper instance to access ImportExportToolProvider methods
    // This allows us to reuse logic from disabled tools and benefit from upstream updates
    private final ImportExportToolProvider importExportHelper;

    /**
     * Constructor
     * @param server The MCP server
     */
    public CrossReferencesToolProvider(McpSyncServer server) {
        super(server);
        // Create helper instance to access protected methods from disabled tool provider
        this.importExportHelper = new ImportExportToolProvider(server);
    }

    /**
     * Result of a safe decompilation attempt. Encapsulates either a successful
     * decompilation result or an error message.
     */
    private record DecompilationAttempt(
        DecompileResults results,
        String errorMessage,
        boolean success
    ) {
        static DecompilationAttempt success(DecompileResults results) {
            return new DecompilationAttempt(results, null, true);
        }

        static DecompilationAttempt failure(String message) {
            return new DecompilationAttempt(null, message, false);
        }
    }

    /**
     * Helper record to track address and thunk information for import references.
     */
    private record AddressWithThunkInfo(Address address, Address thunkAddress) {}

    @Override
    public void registerTools() {
        registerCrossReferencesTool();
    }

    /**
     * Register the get-references tool
     */
    private void registerCrossReferencesTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        Map<String, Object> targetProperty = new HashMap<>();
        targetProperty.put("type", "string");
        targetProperty.put("description", "Target address, symbol name, function name, or import name. Can be a single string or an array of strings for batch operations.");
        Map<String, Object> targetArraySchema = new HashMap<>();
        targetArraySchema.put("type", "array");
        targetArraySchema.put(
            "items",
            Map.of("type", "string")
        );
        targetArraySchema.put(
            "description",
            "Array of target addresses, symbols, function names, or import names for batch operations"
        );
        targetProperty.put("oneOf", List.of(
            Map.of("type", "string"),
            targetArraySchema
        ));
        properties.put("target", targetProperty);
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Reference mode: 'to', 'from', 'both', 'function', 'referencers_decomp', 'import', 'thunk'",
            "enum", List.of("to", "from", "both", "function", "referencers_decomp", "import", "thunk"),
            "default", "both"
        ));
        properties.put("direction", Map.of(
            "type", "string",
            "description", "Direction filter when mode='both': 'to', 'from', or 'both'",
            "enum", List.of("to", "from", "both"),
            "default", "both"
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Pagination offset",
            "default", 0
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Maximum number of references to return",
            "default", 100
        ));
        properties.put("max_results", Map.of(
            "type", "integer",
            "description", "Alternative limit parameter for import mode",
            "default", 100
        ));
        properties.put("library_name", Map.of(
            "type", "string",
            "description", "Optional specific library name to narrow search when mode='import' (case-insensitive)"
        ));
        properties.put("start_index", Map.of(
            "type", "integer",
            "description", "Starting index for pagination when mode='referencers_decomp' (0-based)",
            "default", 0
        ));
        properties.put("max_referencers", Map.of(
            "type", "integer",
            "description", "Maximum number of referencing functions to decompile when mode='referencers_decomp'",
            "default", 10
        ));
        properties.put("include_ref_context", Map.of(
            "type", "boolean",
            "description", "Whether to include reference line numbers in decompilation when mode='referencers_decomp'",
            "default", true
        ));
        properties.put("include_data_refs", Map.of(
            "type", "boolean",
            "description", "Whether to include data references (reads/writes), not just calls when mode='referencers_decomp'",
            "default", true
        ));

        List<String> required = List.of("programPath", "target");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-references")
            .title("Get References")
            .description("Find and analyze references to/from addresses, symbols, functions, or imports, with optional decompilation of referencers.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);

                // Check if target is an array (batch mode)
                Object targetValue = request.arguments().get("target");
                if (targetValue instanceof List) {
                    return handleBatchGetReferences(program, request, (List<?>) targetValue);
                }

                // Single target mode
                String target = getString(request, "target");
                String mode = getOptionalString(request, "mode", "both");

                switch (mode) {
                    case "to":
                        return handleReferencesToMode(program, target, request);
                    case "from":
                        return handleReferencesFromMode(program, target, request);
                    case "both":
                        return handleReferencesBothMode(program, target, request);
                    case "function":
                        return handleReferencesFunctionMode(program, target, request);
                    case "referencers_decomp":
                        return handleReferencersDecompiledMode(program, target, request);
                    case "import":
                        return handleImportReferencesMode(program, target, request);
                    case "thunk":
                        return handleThunkMode(program, target, request);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: to, from, both, function, referencers_decomp, import, thunk");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in get-references", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleReferencesToMode(Program program, String target, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Address address = AddressUtil.resolveAddressOrSymbol(program, target);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + target);
        }
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);

        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        ReferenceManager refManager = program.getReferenceManager();
        List<Map<String, Object>> references = new ArrayList<>();

        if (!address.isStackAddress() && !address.isRegisterAddress()) {
            ReferenceIterator refIter = refManager.getReferencesTo(address);
            List<Map<String, Object>> allRefs = new ArrayList<>();

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                allRefs.add(createReferenceInfo(ref, program, false, 2, true));
            }

            int endIndex = Math.min(offset + limit, allRefs.size());
            if (offset < allRefs.size()) {
                references = allRefs.subList(offset, endIndex);
            }

            Map<String, Object> result = new HashMap<>();
            result.put("references", references);
            result.put("referencesFrom", new ArrayList<>());
            result.put("totalCount", allRefs.size());
            result.put("offset", offset);
            result.put("limit", limit);
            result.put("hasMore", offset + limit < allRefs.size());
            return createJsonResult(result);
        }

        return createJsonResult(Map.of("references", references, "referencesFrom", new ArrayList<>(), "totalCount", 0));
    }

    private McpSchema.CallToolResult handleReferencesFromMode(Program program, String target, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Address address = AddressUtil.resolveAddressOrSymbol(program, target);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + target);
        }
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);

        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        ReferenceManager refManager = program.getReferenceManager();
        List<Map<String, Object>> allRefs = new ArrayList<>();

        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function != null) {
            for (Address addr : function.getBody().getAddresses(true)) {
                Reference[] refs = refManager.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    allRefs.add(createReferenceInfo(ref, program, false, 2, false));
                }
            }
        } else {
            Reference[] refs = refManager.getReferencesFrom(address);
            for (Reference ref : refs) {
                allRefs.add(createReferenceInfo(ref, program, false, 2, false));
            }
        }

        int endIndex = Math.min(offset + limit, allRefs.size());
        List<Map<String, Object>> references = offset < allRefs.size() ? allRefs.subList(offset, endIndex) : new ArrayList<>();

        Map<String, Object> result = new HashMap<>();
        result.put("references", references);
        result.put("totalCount", allRefs.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("hasMore", offset + limit < allRefs.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleReferencesBothMode(Program program, String target, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Address address = AddressUtil.resolveAddressOrSymbol(program, target);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + target);
        }
        String direction = getOptionalString(request, "direction", "both");
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);

        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        boolean includeTo = direction.equals("to") || direction.equals("both");
        boolean includeFrom = direction.equals("from") || direction.equals("both");

        List<Map<String, Object>> referencesTo = new ArrayList<>();
        List<Map<String, Object>> referencesFrom = new ArrayList<>();
        int totalToCount = 0;
        int totalFromCount = 0;

        ReferenceManager refManager = program.getReferenceManager();
        SymbolTable symbolTable = program.getSymbolTable();

        if (includeTo && !address.isStackAddress() && !address.isRegisterAddress()) {
            ReferenceIterator refIter = refManager.getReferencesTo(address);
            List<Map<String, Object>> allRefsTo = new ArrayList<>();

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                allRefsTo.add(createReferenceInfo(ref, program, false, 2, true));
            }

            totalToCount = allRefsTo.size();
            int endIndex = Math.min(offset + limit, allRefsTo.size());
            if (offset < allRefsTo.size()) {
                referencesTo = allRefsTo.subList(offset, endIndex);
            }
        }

        if (includeFrom) {
            List<Map<String, Object>> allRefsFrom = new ArrayList<>();
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function != null) {
                for (Address addr : function.getBody().getAddresses(true)) {
                    Reference[] refs = refManager.getReferencesFrom(addr);
                    for (Reference ref : refs) {
                        allRefsFrom.add(createReferenceInfo(ref, program, false, 2, false));
                    }
                }
            } else {
                Reference[] refs = refManager.getReferencesFrom(address);
                for (Reference ref : refs) {
                    allRefsFrom.add(createReferenceInfo(ref, program, false, 2, false));
                }
            }

            totalFromCount = allRefsFrom.size();
            int endIndex = Math.min(offset + limit, allRefsFrom.size());
            if (offset < allRefsFrom.size()) {
                referencesFrom = allRefsFrom.subList(offset, endIndex);
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("referencesTo", referencesTo);
        result.put("referencesFrom", referencesFrom);
        result.put("totalToCount", totalToCount);
        result.put("totalFromCount", totalFromCount);
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("hasMoreTo", offset + limit < totalToCount);
        result.put("hasMoreFrom", offset + limit < totalFromCount);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleReferencesFunctionMode(Program program, String target, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Function function = getFunctionFromArgs(request.arguments(), program, "target");
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);

        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refIter = refManager.getReferencesTo(function.getEntryPoint());
        List<Map<String, Object>> allRefs = new ArrayList<>();

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            allRefs.add(createReferenceInfo(ref, program, false, 2, true));
        }

        int endIndex = Math.min(offset + limit, allRefs.size());
        List<Map<String, Object>> references = offset < allRefs.size() ? allRefs.subList(offset, endIndex) : new ArrayList<>();

        Map<String, Object> result = new HashMap<>();
        result.put("references", references);
        result.put("totalCount", allRefs.size());
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("hasMore", offset + limit < allRefs.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleReferencersDecompiledMode(Program program, String target, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Address targetAddress = AddressUtil.resolveAddressOrSymbol(program, target);
        if (targetAddress == null) {
            return createErrorResult("Could not resolve address or symbol: " + target);
        }

        int maxReferencers = getOptionalInt(request, "max_referencers", 10);
        int startIndex = getOptionalInt(request, "start_index", 0);
        boolean includeRefContext = getOptionalBoolean(request, "include_ref_context", true);
        boolean includeDataRefs = getOptionalBoolean(request, "include_data_refs", true);

        if (maxReferencers <= 0 || maxReferencers > 50) {
            return createErrorResult("max_referencers must be between 1 and 50");
        }
        if (startIndex < 0) {
            return createErrorResult("start_index must be non-negative");
        }

        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refIter = refManager.getReferencesTo(targetAddress);
        Set<Function> referencingFunctions = new HashSet<>();
        Map<Function, List<Map<String, Object>>> refDetails = new HashMap<>();
        // Also store raw addresses for line number lookup
        Map<Function, List<Address>> refAddressesMap = new HashMap<>();

        final int MAX_TOTAL_REFERENCERS = 500;
        while (refIter.hasNext() && referencingFunctions.size() < MAX_TOTAL_REFERENCERS) {
            Reference ref = refIter.next();

            // Filter by reference type if requested
            if (!includeDataRefs && !ref.getReferenceType().isFlow()) {
                continue;
            }

            Address fromAddr = ref.getFromAddress();
            Function refFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
            if (refFunc != null) {
                referencingFunctions.add(refFunc);

                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("fromAddress", AddressUtil.formatAddress(fromAddr));
                refInfo.put("refType", ref.getReferenceType().toString());
                refInfo.put("isCall", ref.getReferenceType().isCall());
                refInfo.put("isData", ref.getReferenceType().isData());
                refInfo.put("isRead", ref.getReferenceType().isRead());
                refInfo.put("isWrite", ref.getReferenceType().isWrite());

                refDetails.computeIfAbsent(refFunc, k -> new ArrayList<>()).add(refInfo);
                // Store raw address for line number lookup
                refAddressesMap.computeIfAbsent(refFunc, k -> new ArrayList<>()).add(fromAddr);
            }
        }

        // Convert to list for pagination
        List<Function> refList = new ArrayList<>(referencingFunctions);
        int totalReferencers = refList.size();

        // Apply pagination
        int endIndex = Math.min(startIndex + maxReferencers, totalReferencers);
        List<Function> pageRefs = startIndex < totalReferencers
            ? refList.subList(startIndex, endIndex)
            : List.of();

        // Get program path for tracking
        String programPath = program.getDomainFile().getPathname();

        // Decompile each referencing function
        List<Map<String, Object>> decompiledFunctions = new ArrayList<>();
        DecompInterface decompiler = createConfiguredDecompilerForReferences(program);

        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }

        try {
            for (Function refFunc : pageRefs) {
                Map<String, Object> funcResult = new HashMap<>();
                funcResult.put("functionName", refFunc.getName());
                funcResult.put("address", AddressUtil.formatAddress(refFunc.getEntryPoint()));
                funcResult.put("references", refDetails.get(refFunc));

                DecompilationAttempt attempt = decompileFunctionSafelyForReferences(decompiler, refFunc);
                if (attempt.success()) {
                    String decompCode = attempt.results().getDecompiledFunction().getC();
                    funcResult.put("decompilation", decompCode);
                    funcResult.put("success", true);

                    // Find reference line numbers if requested using pre-collected addresses
                    if (includeRefContext) {
                        List<Address> refAddresses = refAddressesMap.get(refFunc);
                        if (refAddresses != null) {
                            List<Integer> refLineNumbers = findReferenceLineNumbers(attempt.results(), refAddresses);
                            funcResult.put("referenceLineNumbers", refLineNumbers);
                        }
                    }

                    // Track that this function's decompilation has been read
                    String functionKey = programPath + ":" + AddressUtil.formatAddress(refFunc.getEntryPoint());
                    DecompilationReadTracker.markAsRead(functionKey);
                } else {
                    funcResult.put("success", false);
                    funcResult.put("error", attempt.errorMessage());
                }

                decompiledFunctions.add(funcResult);
            }
        } finally {
            decompiler.dispose();
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", programPath);
        result.put("targetAddress", AddressUtil.formatAddress(targetAddress));
        result.put("resolvedFrom", target);
        result.put("totalReferencers", totalReferencers);
        result.put("startIndex", startIndex);
        result.put("returnedCount", decompiledFunctions.size());
        result.put("nextStartIndex", startIndex + decompiledFunctions.size());
        result.put("hasMore", endIndex < totalReferencers);
        result.put("includeDataRefs", includeDataRefs);
        result.put("referencers", decompiledFunctions);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleImportReferencesMode(Program program, String target, CallToolRequest request) {
        String libraryName = getOptionalString(request, "library_name", null);
        int maxResults = getOptionalInt(request, "max_results", 100);
        if (maxResults <= 0) maxResults = 100;
        if (maxResults > 1000) maxResults = 1000;

        // Find matching imports
        List<Function> matchingImports = findImportsByName(program, target, libraryName);

        if (matchingImports.isEmpty()) {
            return createErrorResult("Import not found: " + target +
                (libraryName != null && !libraryName.isEmpty() ? " in " + libraryName : ""));
        }

        // Build thunk map once for efficiency: external function -> thunks pointing to it
        Map<Function, List<Function>> thunkMap = buildThunkMapForReferences(program);

        // Collect references including through thunks
        List<Map<String, Object>> references = collectImportReferencesWithThunks(
            program, matchingImports, thunkMap, maxResults);

        // Build matched imports info
        List<Map<String, Object>> importInfoList = new ArrayList<>();
        for (Function importFunc : matchingImports) {
            Map<String, Object> info = buildImportInfoForReferences(importFunc);
            importInfoList.add(info);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("searchedImport", target);
        result.put("matchedImports", importInfoList);
        result.put("referenceCount", references.size());
        result.put("references", references);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleThunkMode(Program program, String target, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Address address = AddressUtil.resolveAddressOrSymbol(program, target);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + target);
        }
        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            function = program.getFunctionManager().getFunctionContaining(address);
        }
        if (function == null) {
            return createErrorResult("No function found at address: " + AddressUtil.formatAddress(address));
        }

        // Delegate to ImportExportToolProvider to benefit from upstream updates
        List<Map<String, Object>> chain = importExportHelper.buildThunkChain(function);
        Map<String, Object> finalTarget = chain.get(chain.size() - 1);
        boolean isResolved = !Boolean.TRUE.equals(finalTarget.get("isThunk"));

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("startAddress", AddressUtil.formatAddress(address));
        result.put("chain", chain);
        result.put("chainLength", chain.size());
        result.put("finalTarget", finalTarget);
        result.put("isResolved", isResolved);
        return createJsonResult(result);
    }

    // REMOVED: buildThunkChain method
    // This method has been removed in favor of delegating to ImportExportToolProvider
    // to benefit from upstream updates to disabled tool handlers.
    // See importExportHelper.buildThunkChain()

    /**
     * Create reference information map with optional decompilation context
     * @param ref The reference
     * @param program The program
     * @param includeContext Whether to include decompilation context
     * @param contextLines Number of context lines
     * @param isIncoming Whether this is an incoming reference (to) or outgoing (from)
     * @return Map containing reference information
     */
    private Map<String, Object> createReferenceInfo(Reference ref, Program program,
                                                    boolean includeContext, int contextLines,
                                                    boolean isIncoming) {
        Map<String, Object> refInfo = new HashMap<>();
        SymbolTable symbolTable = program.getSymbolTable();

        // Basic reference information
        refInfo.put("fromAddress", AddressUtil.formatAddress(ref.getFromAddress()));
        refInfo.put("toAddress", AddressUtil.formatAddress(ref.getToAddress()));
        refInfo.put("referenceType", ref.getReferenceType().toString());
        refInfo.put("isPrimary", ref.isPrimary());
        refInfo.put("operandIndex", ref.getOperandIndex());
        refInfo.put("sourceType", ref.getSource().toString());
        refInfo.put("isCall", ref.getReferenceType().isCall());
        refInfo.put("isJump", ref.getReferenceType().isJump());
        refInfo.put("isData", ref.getReferenceType().isData());
        refInfo.put("isRead", ref.getReferenceType().isRead());
        refInfo.put("isWrite", ref.getReferenceType().isWrite());

        // Add symbol information for both addresses
        Symbol fromSymbol = symbolTable.getPrimarySymbol(ref.getFromAddress());
        if (fromSymbol != null) {
            Map<String, Object> fromSymbolInfo = new HashMap<>();
            fromSymbolInfo.put("name", fromSymbol.getName());
            fromSymbolInfo.put("type", fromSymbol.getSymbolType().toString());
            if (!fromSymbol.isGlobal()) {
                fromSymbolInfo.put("namespace", fromSymbol.getParentNamespace().getName(true));
            }
            refInfo.put("fromSymbol", fromSymbolInfo);
        }

        Symbol toSymbol = symbolTable.getPrimarySymbol(ref.getToAddress());
        if (toSymbol != null) {
            Map<String, Object> toSymbolInfo = new HashMap<>();
            toSymbolInfo.put("name", toSymbol.getName());
            toSymbolInfo.put("type", toSymbol.getSymbolType().toString());
            if (!toSymbol.isGlobal()) {
                toSymbolInfo.put("namespace", toSymbol.getParentNamespace().getName(true));
            }
            refInfo.put("toSymbol", toSymbolInfo);
        }

        // Add function information and optional decompilation context
        Address contextAddress = isIncoming ? ref.getFromAddress() : ref.getToAddress();
        Function contextFunction = program.getFunctionManager().getFunctionContaining(contextAddress);

        if (contextFunction != null) {
            Map<String, Object> functionInfo = new HashMap<>();
            functionInfo.put("name", contextFunction.getName());
            functionInfo.put("entry", AddressUtil.formatAddress(contextFunction.getEntryPoint()));

            // For incoming references, add decompilation context from the calling function
            if (includeContext && ref.getReferenceType().isFlow()) {
                int lineNumber = DecompilationContextUtil.getLineNumberForAddress(
                    program, contextFunction, contextAddress);

                if (lineNumber > 0) {
                    functionInfo.put("line", lineNumber);

                    String context = DecompilationContextUtil.getDecompilationContext(
                        program, contextFunction, lineNumber, contextLines);
                    if (context != null) {
                        functionInfo.put("context", context);
                    }
                }
            }

            refInfo.put(isIncoming ? "fromFunction" : "toFunction", functionInfo);
        }

        return refInfo;
    }

    // ========================================================================
    // Decompiler Infrastructure for referencers_decomp mode
    // ========================================================================

    private DecompInterface createConfiguredDecompilerForReferences(Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            logError("get-references: Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    private DecompilationAttempt decompileFunctionSafelyForReferences(
            DecompInterface decompiler,
            Function function) {
        TaskMonitor timeoutMonitor = createTimeoutMonitorForReferences();
        DecompileResults results = decompiler.decompileFunction(function, 0, timeoutMonitor);

        if (timeoutMonitor.isCancelled()) {
            String msg = "Decompilation timed out after " + getTimeoutSecondsForReferences() + " seconds";
            logError("get-references: " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        if (!results.decompileCompleted()) {
            String msg = "Decompilation failed: " + results.getErrorMessage();
            logError("get-references: " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        return DecompilationAttempt.success(results);
    }

    private List<Integer> findReferenceLineNumbers(DecompileResults results, List<Address> addresses) {
        List<Integer> lineNumbers = new ArrayList<>();

        if (results == null || addresses == null || addresses.isEmpty()) {
            return lineNumbers;
        }

        ClangTokenGroup markup = results.getCCodeMarkup();
        if (markup == null) {
            return lineNumbers;
        }

        Set<Address> addressSet = new HashSet<>(addresses);
        List<ClangLine> lines = DecompilerUtils.toLines(markup);

        for (ClangLine line : lines) {
            for (ClangToken token : line.getAllTokens()) {
                Address tokenAddr = token.getMinAddress();
                if (tokenAddr != null && addressSet.contains(tokenAddr)) {
                    lineNumbers.add(line.getLineNumber());
                    break; // Only add line once
                }
            }
        }

        return lineNumbers;
    }

    private TaskMonitor createTimeoutMonitorForReferences() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = configManager != null ? configManager.getDecompilerTimeoutSeconds() : DEFAULT_TIMEOUT_SECONDS;
        return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
    }

    private int getTimeoutSecondsForReferences() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        return configManager != null ? configManager.getDecompilerTimeoutSeconds() : DEFAULT_TIMEOUT_SECONDS;
    }

    // ========================================================================
    // Import/Thunk Helper Methods
    // ========================================================================

    /**
     * Find imports by name, optionally filtered by library name.
     */
    private List<Function> findImportsByName(Program program, String importName, String libraryName) {
        List<Function> matches = new ArrayList<>();
        FunctionIterator externalFunctions = program.getFunctionManager().getExternalFunctions();

        while (externalFunctions.hasNext()) {
            Function func = externalFunctions.next();

            if (!func.getName().equalsIgnoreCase(importName)) {
                continue;
            }

            if (libraryName != null && !libraryName.isEmpty()) {
                ExternalLocation extLoc = func.getExternalLocation();
                if (extLoc == null || !extLoc.getLibraryName().equalsIgnoreCase(libraryName)) {
                    continue;
                }
            }

            matches.add(func);
        }

        return matches;
    }

    /**
     * Build a map from external functions to thunks that point to them.
     * This is O(n) where n = number of functions, done once per request.
     */
    private Map<Function, List<Function>> buildThunkMapForReferences(Program program) {
        Map<Function, List<Function>> thunkMap = new HashMap<>();
        FunctionIterator allFunctions = program.getFunctionManager().getFunctions(true);

        while (allFunctions.hasNext()) {
            Function func = allFunctions.next();
            if (func.isThunk()) {
                Function target = func.getThunkedFunction(true); // Resolve fully
                if (target != null && target.isExternal()) {
                    thunkMap.computeIfAbsent(target, k -> new ArrayList<>()).add(func);
                }
            }
        }

        return thunkMap;
    }

    /**
     * Collect import references including references through thunks.
     */
    private List<Map<String, Object>> collectImportReferencesWithThunks(
            Program program,
            List<Function> matchingImports,
            Map<Function, List<Function>> thunkMap,
            int maxResults) {

        List<Map<String, Object>> references = new ArrayList<>();
        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        Set<Address> seen = new HashSet<>();

        for (Function importFunc : matchingImports) {
            if (references.size() >= maxResults) break;

            // Collect all addresses to check: the import and its thunks
            List<AddressWithThunkInfo> targets = new ArrayList<>();

            Address importAddr = importFunc.getEntryPoint();
            if (importAddr != null) {
                targets.add(new AddressWithThunkInfo(importAddr, null));
            }

            List<Function> thunks = thunkMap.get(importFunc);
            if (thunks != null) {
                for (Function thunk : thunks) {
                    Address thunkAddr = thunk.getEntryPoint();
                    if (thunkAddr != null) {
                        targets.add(new AddressWithThunkInfo(thunkAddr, thunkAddr));
                    }
                }
            }

            // Get references to all targets
            for (AddressWithThunkInfo target : targets) {
                if (references.size() >= maxResults) break;

                ReferenceIterator refIter = refManager.getReferencesTo(target.address);
                while (refIter.hasNext() && references.size() < maxResults) {
                    Reference ref = refIter.next();
                    Address fromAddr = ref.getFromAddress();

                    if (seen.contains(fromAddr)) continue;
                    seen.add(fromAddr);

                    Map<String, Object> refInfo = createReferenceInfo(ref, program, false, 2, true);

                    // Add import-specific information
                    refInfo.put("importName", importFunc.getName());
                    ExternalLocation extLoc = importFunc.getExternalLocation();
                    if (extLoc != null) {
                        refInfo.put("library", extLoc.getLibraryName());
                    }

                    // Indicate if reference is through a thunk
                    if (target.thunkAddress != null) {
                        refInfo.put("viaThunk", true);
                        refInfo.put("thunkAddress", AddressUtil.formatAddress(target.thunkAddress));
                    }

                    references.add(refInfo);
                }
            }
        }

        return references;
    }

    /**
     * Build import information map.
     */
    private Map<String, Object> buildImportInfoForReferences(Function importFunc) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", importFunc.getName());
        Address entryPoint = importFunc.getEntryPoint();
        if (entryPoint != null) {
            info.put("address", AddressUtil.formatAddress(entryPoint));
        }

        ExternalLocation extLoc = importFunc.getExternalLocation();
        if (extLoc != null) {
            info.put("library", extLoc.getLibraryName());
            String originalName = extLoc.getOriginalImportedName();
            if (originalName != null && !originalName.equals(importFunc.getName())) {
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

        if (importFunc.getSignature() != null) {
            info.put("signature", importFunc.getSignature().getPrototypeString());
        }

        return info;
    }

    /**
     * Handle batch get-references operations when target is an array
     */
    private McpSchema.CallToolResult handleBatchGetReferences(Program program, CallToolRequest request, List<?> targetList) {
        String mode = getOptionalString(request, "mode", "both");
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        for (int i = 0; i < targetList.size(); i++) {
            try {
                String target = targetList.get(i).toString();
                Map<String, Object> targetResult = new HashMap<>();
                targetResult.put("index", i);
                targetResult.put("target", target);

                McpSchema.CallToolResult singleResult;
                switch (mode) {
                    case "to":
                        singleResult = handleReferencesToMode(program, target, request);
                        break;
                    case "from":
                        singleResult = handleReferencesFromMode(program, target, request);
                        break;
                    case "both":
                        singleResult = handleReferencesBothMode(program, target, request);
                        break;
                    case "function":
                        singleResult = handleReferencesFunctionMode(program, target, request);
                        break;
                    case "referencers_decomp":
                        singleResult = handleReferencersDecompiledMode(program, target, request);
                        break;
                    case "import":
                        singleResult = handleImportReferencesMode(program, target, request);
                        break;
                    case "thunk":
                        singleResult = handleThunkMode(program, target, request);
                        break;
                    default:
                        errors.add(Map.of("index", i, "target", target, "error", "Invalid mode: " + mode));
                        continue;
                }

                if (singleResult.isError()) {
                    String errorText = extractTextFromContent(singleResult.content().get(0));
                    errors.add(Map.of("index", i, "target", target, "error", errorText));
                } else {
                    Map<String, Object> resultData = extractJsonDataFromResult(singleResult);
                    targetResult.putAll(resultData);
                    results.add(targetResult);
                }
            } catch (Exception e) {
                errors.add(Map.of("index", i, "target", targetList.get(i).toString(), "error", e.getMessage()));
            }
        }

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("success", true);
        resultData.put("mode", mode);
        resultData.put("total", targetList.size());
        resultData.put("succeeded", results.size());
        resultData.put("failed", errors.size());
        resultData.put("results", results);
        if (!errors.isEmpty()) {
            resultData.put("errors", errors);
        }

        return createJsonResult(resultData);
    }

    /**
     * Extract JSON data from a CallToolResult, returning the parsed map
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractJsonDataFromResult(McpSchema.CallToolResult result) {
        try {
            String jsonText = extractTextFromContent(result.content().get(0));
            return JSON.readValue(jsonText, Map.class);
        } catch (Exception e) {
            logError("Error extracting JSON data from result", e);
            return new HashMap<>();
        }
    }

    /**
     * Helper method to extract text from Content object
     */
    private String extractTextFromContent(McpSchema.Content content) {
        if (content instanceof io.modelcontextprotocol.spec.McpSchema.TextContent) {
            return ((io.modelcontextprotocol.spec.McpSchema.TextContent) content).text();
        }
        return content.toString();
    }
}
