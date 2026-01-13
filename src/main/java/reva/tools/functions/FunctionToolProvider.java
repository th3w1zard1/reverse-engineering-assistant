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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SimilarityComparator;
import reva.util.SymbolUtil;
import reva.util.DataTypeParserUtil;
import reva.util.DecompilationDiffUtil;
import reva.util.RevaInternalServiceRegistry;
import reva.util.SmartSuggestionsUtil;
import reva.util.SchemaUtil;
import reva.plugin.ConfigManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tool provider for function-related operations.
 */
public class FunctionToolProvider extends AbstractToolProvider {

    /** Maximum number of cached similarity search results */
    private static final int MAX_CACHE_ENTRIES = 50;

    /** Cache expiration time in milliseconds (10 minutes) */
    private static final long CACHE_EXPIRATION_MS = 10 * 60 * 1000;

    /** Timeout for similarity search operations in seconds */
    private static final int SIMILARITY_SEARCH_TIMEOUT_SECONDS = 120;

    /** Maximum number of results to cache per search (prevents memory bloat) */
    private static final int MAX_CACHED_RESULTS_PER_SEARCH = 2000;

    /** Log a warning if similarity search takes longer than this (milliseconds) */
    private static final long SLOW_SEARCH_THRESHOLD_MS = 5000;

    /** Maximum function info cache entries (one per program/filter combination) */
    private static final int MAX_FUNCTION_INFO_CACHE_ENTRIES = 10;

    /** Timeout for building function info cache in seconds */
    private static final int FUNCTION_INFO_CACHE_TIMEOUT_SECONDS = 300;

    /** Maximum unique candidates to track before early termination (memory protection) */
    private static final int MAX_UNIQUE_CANDIDATES = 10000;

    /** Memory block patterns to exclude from undefined function candidates (PLT, GOT, imports) */
    private static final Set<String> EXCLUDED_BLOCK_PATTERNS = Set.of(
        ".plt", ".got", ".idata", ".edata", "extern", "external"
    );

    /** Valid modes for the function-tags tool */
    private static final Set<String> VALID_TAG_MODES = Set.of("get", "set", "add", "remove", "list");

    /**
     * Cache key for similarity search results.
     */
    private record SimilarityCacheKey(String programPath, String searchString, boolean filterDefaultNames) {}

    /**
     * Cached similarity search result with metadata.
     */
    private record CachedSearchResult(
        List<Map<String, Object>> sortedFunctions,
        long timestamp,
        int totalCount,
        long programModificationNumber
    ) {
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_EXPIRATION_MS;
        }
    }

    /**
     * Thread-safe cache for similarity search results.
     * Uses ConcurrentHashMap for safe concurrent access.
     * Eviction is handled manually to respect MAX_CACHE_ENTRIES.
     */
    private final ConcurrentHashMap<SimilarityCacheKey, CachedSearchResult> similarityCache =
        new ConcurrentHashMap<>();

    /**
     * Cache key for raw function info (shared between get-functions and get-functions-by-similarity).
     */
    private record FunctionInfoCacheKey(String programPath, boolean filterDefaultNames) {}

    /**
     * Cached function info list with metadata.
     */
    private record CachedFunctionInfo(
        List<Map<String, Object>> functions,
        long timestamp,
        long programModificationNumber
    ) {
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_EXPIRATION_MS;
        }
    }

    /**
     * Thread-safe cache for raw function info (shared between listing tools).
     * Computing function info is expensive due to caller/callee counts.
     */
    private final ConcurrentHashMap<FunctionInfoCacheKey, CachedFunctionInfo> functionInfoCache =
        new ConcurrentHashMap<>();

    /**
     * Helper class to track undefined function candidate info including reference types.
     */
    private static class CandidateInfo {
        private final List<Address> references = new ArrayList<>();
        private boolean hasCallRef = false;
        private boolean hasDataRef = false;

        void addReference(Address fromAddr, boolean isCall, boolean isData) {
            references.add(fromAddr);
            if (isCall) hasCallRef = true;
            if (isData) hasDataRef = true;
        }

        int referenceCount() { return references.size(); }
        List<Address> references() { return references; }
        boolean hasCallRef() { return hasCallRef; }
        boolean hasDataRef() { return hasDataRef; }
    }

    /**
     * Constructor
     * @param server The MCP server
     */
    public FunctionToolProvider(McpSyncServer server) {
        super(server);
    }

    /**
     * Invalidate function caches for a specific program.
     * Called after modifications that change function metadata (e.g., tags).
     * Clears both functionInfoCache and similarityCache since both contain function data with tags.
     */
    private void invalidateFunctionCaches(String programPath) {
        functionInfoCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
        similarityCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
    }

    /**
     * Clear cached results when a program is closed.
     */
    @Override
    public void programClosed(Program program) {
        super.programClosed(program);

        String programPath = program.getDomainFile().getPathname();

        // Clear similarity cache using removeIf (thread-safe, no iterator-while-modifying)
        int beforeSimilarity = similarityCache.size();
        similarityCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
        int removedSimilarity = beforeSimilarity - similarityCache.size();

        // Clear function info cache using removeIf (thread-safe, no iterator-while-modifying)
        int beforeFunctionInfo = functionInfoCache.size();
        functionInfoCache.entrySet().removeIf(entry -> entry.getKey().programPath().equals(programPath));
        int removedFunctionInfo = beforeFunctionInfo - functionInfoCache.size();

        if (removedSimilarity > 0 || removedFunctionInfo > 0) {
            logInfo("FunctionToolProvider: Cleared " + removedSimilarity +
                " similarity cache entries and " + removedFunctionInfo +
                " function info cache entries for closed program: " + programPath);
        }
    }

    /**
     * Get function info list from cache or build it.
     * This is the shared cache used by both get-functions and get-functions-by-similarity.
     *
     * @param program The program to get function info from
     * @param filterDefaultNames Whether to filter out default Ghidra names
     * @return List of function info maps (never null, but may be empty if timeout)
     */
    private List<Map<String, Object>> getOrBuildFunctionInfoCache(Program program, boolean filterDefaultNames) {
        String programPath = program.getDomainFile().getPathname();
        FunctionInfoCacheKey cacheKey = new FunctionInfoCacheKey(programPath, filterDefaultNames);
        long currentModNumber = program.getModificationNumber();

        // Check cache first (thread-safe read)
        CachedFunctionInfo cached = functionInfoCache.get(cacheKey);
        if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
            logInfo("FunctionToolProvider: Using cached function info for " + programPath);
            return cached.functions();
        }

        // Synchronize cache building to prevent duplicate work from concurrent requests
        synchronized (functionInfoCache) {
            // Double-check after acquiring lock (another thread may have built it)
            cached = functionInfoCache.get(cacheKey);
            if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
                return cached.functions();
            }

            // Build function info list with timeout support
            logInfo("FunctionToolProvider: Building function info cache for " + programPath);
            long startTime = System.currentTimeMillis();

            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(FUNCTION_INFO_CACHE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            List<Map<String, Object>> functionList = new ArrayList<>();
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            int processed = 0;

            while (functions.hasNext()) {
                // Check for timeout periodically
                if (processed % 100 == 0 && monitor.isCancelled()) {
                    logInfo("FunctionToolProvider: Cache build timed out after " + processed + " functions");
                    break;
                }

                Function function = functions.next();
                processed++;

                // Skip default Ghidra function names if filtering is enabled
                if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                    continue;
                }

                functionList.add(createFunctionInfo(function, monitor));
            }

            // Enforce cache size limit before adding new entry
            evictFunctionInfoCacheIfNeeded();

            // Cache the results
            CachedFunctionInfo newCached = new CachedFunctionInfo(
                List.copyOf(functionList),
                System.currentTimeMillis(),
                currentModNumber
            );
            functionInfoCache.put(cacheKey, newCached);

            long elapsed = System.currentTimeMillis() - startTime;
            if (elapsed > SLOW_SEARCH_THRESHOLD_MS) {
                logInfo("FunctionToolProvider: Building function info cache took " +
                    (elapsed / 1000) + "s (" + functionList.size() + " functions)");
            }

            return functionList;
        }
    }

    /**
     * Evict oldest function info cache entries if cache is at capacity.
     * Must be called while holding functionInfoCache lock.
     */
    private void evictFunctionInfoCacheIfNeeded() {
        // Remove expired entries first
        functionInfoCache.entrySet().removeIf(entry -> entry.getValue().isExpired());

        // Evict oldest entries if still over limit
        while (functionInfoCache.size() >= MAX_FUNCTION_INFO_CACHE_ENTRIES) {
            FunctionInfoCacheKey oldest = null;
            long oldestTime = Long.MAX_VALUE;
            for (var entry : functionInfoCache.entrySet()) {
                if (entry.getValue().timestamp() < oldestTime) {
                    oldestTime = entry.getValue().timestamp();
                    oldest = entry.getKey();
                }
            }
            if (oldest != null) {
                functionInfoCache.remove(oldest);
                logInfo("FunctionToolProvider: Evicted function info cache entry for: " + oldest.programPath());
            } else {
                break;
            }
        }
    }

    /**
     * Evict expired similarity cache entries.
     * Must be called while holding similarityCache lock.
     */
    private void evictExpiredCacheEntries() {
        similarityCache.entrySet().removeIf(entry -> entry.getValue().isExpired());

        // Evict oldest entries if still over limit
        while (similarityCache.size() >= MAX_CACHE_ENTRIES) {
            SimilarityCacheKey oldest = null;
            long oldestTime = Long.MAX_VALUE;
            for (var entry : similarityCache.entrySet()) {
                if (entry.getValue().timestamp() < oldestTime) {
                    oldestTime = entry.getValue().timestamp();
                    oldest = entry.getKey();
                }
            }
            if (oldest != null) {
                similarityCache.remove(oldest);
                logInfo("FunctionToolProvider: Evicted similarity cache entry for: " + oldest.programPath());
            } else {
                break;
            }
        }
    }

    /**
     * Create a function info map from a Function object.
     *
     * @param function The function to create info for
     * @param monitor TaskMonitor for timeout checking (can be null)
     * @return Map containing function information
     */
    private Map<String, Object> createFunctionInfo(Function function, TaskMonitor monitor) {
        AddressSetView body = function.getBody();

        // Get caller/callee counts with timeout support
        int callerCount = -1;
        int calleeCount = -1;
        if (monitor != null && !monitor.isCancelled()) {
            try {
                ReferenceManager refManager = function.getProgram().getReferenceManager();
                FunctionManager funcManager = function.getProgram().getFunctionManager();

                // Count callers (references TO this function)
                Set<Address> callerAddresses = new HashSet<>();
                ReferenceIterator refsTo = refManager.getReferencesTo(function.getEntryPoint());
                int refCount = 0;
                while (refsTo.hasNext()) {
                    if (++refCount % 1000 == 0 && monitor.isCancelled()) {
                        break;
                    }
                    Reference ref = refsTo.next();
                    if (ref.getReferenceType().isCall()) {
                        Function caller = funcManager.getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            callerAddresses.add(caller.getEntryPoint());
                        }
                    }
                }
                callerCount = monitor.isCancelled() ? -1 : callerAddresses.size();

                // Count callees (references FROM this function)
                if (!monitor.isCancelled()) {
                    Set<Address> calleeAddresses = new HashSet<>();
                    for (Instruction instr : function.getProgram().getListing().getInstructions(body, true)) {
                        if (monitor.isCancelled()) break;
                        Reference[] refsFrom = instr.getReferencesFrom();
                        for (Reference ref : refsFrom) {
                            if (ref.getReferenceType().isCall()) {
                                Function callee = funcManager.getFunctionAt(ref.getToAddress());
                                if (callee == null) {
                                    callee = funcManager.getFunctionContaining(ref.getToAddress());
                                }
                                if (callee != null) {
                                    calleeAddresses.add(callee.getEntryPoint());
                                }
                            }
                        }
                    }
                    calleeCount = monitor.isCancelled() ? -1 : calleeAddresses.size();
                }
            } catch (Exception e) {
                // If counting fails, leave as -1
            }
        }

        // Build parameters list
        List<Map<String, Object>> parametersList = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            Parameter param = function.getParameter(i);
            parametersList.add(Map.of(
                "name", param.getName(),
                "dataType", param.getDataType().toString()
            ));
        }

        // Get function tags
        List<String> tagNames = new ArrayList<>();
        Set<FunctionTag> tags = function.getTags();
        for (FunctionTag tag : tags) {
            tagNames.add(tag.getName());
        }
        Collections.sort(tagNames);

        Map<String, Object> functionData = new HashMap<>();
        functionData.put("name", function.getName());
        functionData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        functionData.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
        functionData.put("sizeInBytes", body.getNumAddresses());
        functionData.put("signature", function.getSignature().toString());
        functionData.put("returnType", function.getReturnType().toString());
        functionData.put("isExternal", function.isExternal());
        functionData.put("isThunk", function.isThunk());
        functionData.put("isDefaultName", SymbolUtil.isDefaultSymbolName(function.getName()));
        functionData.put("callerCount", callerCount);
        functionData.put("calleeCount", calleeCount);
        functionData.put("parameters", parametersList);
        functionData.put("tags", tagNames);

        return functionData;
    }

    /**
     * Normalize a function signature string by trimming whitespace.
     *
     * @param signature The signature string to normalize
     * @return Normalized signature
     */
    private String normalizeFunctionSignature(String signature) {
        if (signature == null) {
            return "";
        }
        return signature.trim();
    }

    /**
     * Check if a function needs custom variable storage for the given signature.
     *
     * @param function The existing function (may be null)
     * @param functionDef The new function definition
     * @return true if custom storage is needed
     */
    private boolean needsCustomStorageForSignature(Function function, FunctionDefinitionDataType functionDef) {
        // If function already has custom storage, keep it
        if (function != null && function.hasCustomVariableStorage()) {
            return true;
        }
        // Otherwise, use default storage (Ghidra will handle it)
        return false;
    }

    @Override
    public void registerTools() {
        registerListFunctionsTool();
        registerManageFunctionTool();
        registerFunctionTagsTool();
    }

    /**
     * Register the list-functions tool: List, search, or count functions in the program with various filtering and search modes.
     */
    private void registerListFunctionsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Operation mode: 'all' (list all functions), 'search' (substring search), 'similarity' (similarity search), 'undefined' (undefined candidates), 'count' (count only)",
            "enum", List.of("all", "search", "similarity", "undefined", "count"),
            "default", "all"
        ));
        properties.put("query", Map.of(
            "type", "string",
            "description", "Substring to search for when mode='search' (required for search mode)"
        ));
        properties.put("search_string", Map.of(
            "type", "string",
            "description", "Function name to compare against for similarity when mode='similarity' (required for similarity mode)"
        ));
        properties.put("min_reference_count", Map.of(
            "type", "integer",
            "description", "Minimum number of references required when mode='undefined' (default: 1)",
            "default", 1
        ));
        properties.put("start_index", Map.of(
            "type", "integer",
            "description", "Starting index for pagination (0-based, default: 0)",
            "default", 0
        ));
        properties.put("max_count", Map.of(
            "type", "integer",
            "description", "Maximum number of functions to return (default: 100)",
            "default", 100
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Alternative pagination offset parameter (default: 0)",
            "default", 0
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Alternative pagination limit parameter (default: 100)",
            "default", 100
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of functions to return (alternative to max_count/limit, default: 100)",
            "default", 1000
        ));
        properties.put("filter_default_names", Map.of(
            "type", "boolean",
            "description", "Whether to filter out default Ghidra generated names like FUN_, DAT_, etc. (default: true)",
            "default", true
        ));
        properties.put("filterByTag", Map.of(
            "type", "string",
            "description", "Only return functions with this tag (applied after filterDefaultNames, only for mode='all')"
        ));
        properties.put("untagged", Map.of(
            "type", "boolean",
            "description", "Only return functions with no tags (mutually exclusive with filterByTag, only for mode='all')",
            "default", false
        ));
        properties.put("verbose", Map.of(
            "type", "boolean",
            "description", "Return full function details. When false (default), returns compact results",
            "default", false
        ));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-functions")
            .title("List Functions")
            .description("List, search, or count functions in the program with various filtering and search modes.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String mode = getOptionalString(request, "mode", "all");

                // Handle pagination
                int startIndex;
                int maxCount;
                if (request.arguments() != null && request.arguments().containsKey("offset")) {
                    int offset = getOptionalInt(request, "offset", 0);
                    int limit = getOptionalInt(request, "limit", 100);
                    startIndex = offset;
                    maxCount = limit;
                } else {
                    // Use start_index/max_count (new standard)
                    // maxResults/max_results handled dynamically
                    startIndex = getOptionalInt(request, "start_index", 0);
                    maxCount = getOptionalInt(request, "max_count", 100);
                }

                boolean filterDefaultNames = getOptionalBoolean(request, "filter_default_names", true);

                switch (mode) {
                    case "count":
                        return handleListFunctionsCount(program, filterDefaultNames);
                    case "all":
                        String filterByTag = getOptionalString(request, "filterByTag", null);
                        boolean untagged = getOptionalBoolean(request, "untagged", false);
                        boolean verbose = getOptionalBoolean(request, "verbose", false);
                        return handleListFunctionsAll(program, startIndex, maxCount, filterDefaultNames, filterByTag, untagged, verbose);
                    case "search":
                        String query = getOptionalString(request, "query", null);
                        if (query == null || query.trim().isEmpty()) {
                            return createErrorResult("query parameter is required when mode='search'");
                        }
                        verbose = getOptionalBoolean(request, "verbose", false);
                        return handleListFunctionsSearch(program, query, startIndex, maxCount, filterDefaultNames, verbose);
                    case "similarity":
                        String searchString = getOptionalString(request, "search_string", null);
                        if (searchString == null || searchString.trim().isEmpty()) {
                            return createErrorResult("search_string parameter is required when mode='similarity'");
                        }
                        verbose = getOptionalBoolean(request, "verbose", false);
                        return handleListFunctionsSimilarity(program, searchString, startIndex, maxCount, filterDefaultNames, verbose);
                    case "undefined":
                        int minReferenceCount = getOptionalInt(request, "min_reference_count", 1);
                        if (minReferenceCount < 1) {
                            return createErrorResult("min_reference_count must be at least 1");
                        }
                        return handleListFunctionsUndefined(program, startIndex, maxCount, minReferenceCount);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: all, search, similarity, undefined, count");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in list-functions", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    /**
     * Handle list-functions mode='count' - count functions
     */
    private McpSchema.CallToolResult handleListFunctionsCount(Program program, boolean filterDefaultNames) {
        AtomicInteger count = new AtomicInteger(0);
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        functions.forEach(function -> {
            if (filterDefaultNames && SymbolUtil.isDefaultSymbolName(function.getName())) {
                return;
            }
            count.incrementAndGet();
        });

        Map<String, Object> result = new HashMap<>();
        result.put("count", count.get());
        result.put("filterDefaultNames", filterDefaultNames);
        return createJsonResult(result);
    }

    /**
     * Handle list-functions mode='all' - list all functions
     */
    private McpSchema.CallToolResult handleListFunctionsAll(Program program, int startIndex, int maxCount,
            boolean filterDefaultNames, String filterByTag, boolean untagged, boolean verbose) {
        // Check mutual exclusivity
        if (untagged && filterByTag != null && !filterByTag.isEmpty()) {
            return createErrorResult("Cannot use both 'untagged' and 'filterByTag' - they are mutually exclusive");
        }

        // Get function info from shared cache (or build it)
        List<Map<String, Object>> allFunctions = getOrBuildFunctionInfoCache(program, filterDefaultNames);

        // Apply tag filter if specified
        List<Map<String, Object>> filteredFunctions;
        if (untagged) {
            filteredFunctions = allFunctions.stream()
                .filter(f -> {
                    @SuppressWarnings("unchecked")
                    List<String> tags = (List<String>) f.get("tags");
                    return tags == null || tags.isEmpty();
                })
                .toList();
        } else if (filterByTag != null && !filterByTag.isEmpty()) {
            filteredFunctions = allFunctions.stream()
                .filter(f -> {
                    @SuppressWarnings("unchecked")
                    List<String> tags = (List<String>) f.get("tags");
                    return tags != null && tags.contains(filterByTag);
                })
                .toList();
        } else {
            filteredFunctions = allFunctions;
        }

        int totalCount = filteredFunctions.size();

        // Apply pagination
        int endIndex = Math.min(startIndex + maxCount, totalCount);
        List<Map<String, Object>> paginatedData = startIndex < totalCount
            ? filteredFunctions.subList(startIndex, endIndex)
            : Collections.emptyList();

        // Transform results based on verbose flag
        List<Map<String, Object>> functionData;
        if (verbose) {
            functionData = paginatedData;
        } else {
            functionData = new ArrayList<>(paginatedData.size());
            for (Map<String, Object> funcInfo : paginatedData) {
                Map<String, Object> compactInfo = new HashMap<>();
                compactInfo.put("name", funcInfo.get("name"));
                compactInfo.put("address", funcInfo.get("address"));
                compactInfo.put("sizeInBytes", funcInfo.get("sizeInBytes"));
                compactInfo.put("tags", funcInfo.get("tags"));
                compactInfo.put("callerCount", funcInfo.get("callerCount"));
                compactInfo.put("calleeCount", funcInfo.get("calleeCount"));
                functionData.add(compactInfo);
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("functions", functionData);
        result.put("startIndex", startIndex);
        result.put("requestedCount", maxCount);
        result.put("actualCount", functionData.size());
        result.put("nextStartIndex", startIndex + functionData.size());
        result.put("totalCount", totalCount);
        result.put("filterDefaultNames", filterDefaultNames);
        result.put("verbose", verbose);
        if (filterByTag != null && !filterByTag.isEmpty()) {
            result.put("filterByTag", filterByTag);
        }
        if (untagged) {
            result.put("untagged", true);
        }
        return createJsonResult(result);
    }

    /**
     * Handle list-functions mode='search' - substring search
     */
    private McpSchema.CallToolResult handleListFunctionsSearch(Program program, String query, int startIndex, int maxCount,
            boolean filterDefaultNames, boolean verbose) {
        if (query.trim().isEmpty()) {
            return createErrorResult("query cannot be empty");
        }

        List<Map<String, Object>> allFunctions = getOrBuildFunctionInfoCache(program, filterDefaultNames);
        String queryLower = query.toLowerCase();

        // Filter by substring match
        List<Map<String, Object>> matchingFunctions = allFunctions.stream()
            .filter(f -> {
                String name = (String) f.get("name");
                return name != null && name.toLowerCase().contains(queryLower);
            })
            .toList();

        int totalCount = matchingFunctions.size();
        int endIndex = Math.min(startIndex + maxCount, totalCount);
        List<Map<String, Object>> paginatedData = startIndex < totalCount
            ? matchingFunctions.subList(startIndex, endIndex)
            : Collections.emptyList();

        // Transform results
        List<Map<String, Object>> functionData;
        if (verbose) {
            functionData = paginatedData;
        } else {
            functionData = new ArrayList<>(paginatedData.size());
            for (Map<String, Object> funcInfo : paginatedData) {
                Map<String, Object> compactInfo = new HashMap<>();
                compactInfo.put("name", funcInfo.get("name"));
                compactInfo.put("address", funcInfo.get("address"));
                compactInfo.put("sizeInBytes", funcInfo.get("sizeInBytes"));
                compactInfo.put("tags", funcInfo.get("tags"));
                compactInfo.put("callerCount", funcInfo.get("callerCount"));
                compactInfo.put("calleeCount", funcInfo.get("calleeCount"));
                functionData.add(compactInfo);
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("functions", functionData);
        result.put("query", query);
        result.put("startIndex", startIndex);
        result.put("requestedCount", maxCount);
        result.put("actualCount", functionData.size());
        result.put("nextStartIndex", startIndex + functionData.size());
        result.put("totalCount", totalCount);
        result.put("filterDefaultNames", filterDefaultNames);
        result.put("verbose", verbose);
        return createJsonResult(result);
    }

    /**
     * Handle list-functions mode='similarity' - similarity search
     */
    private McpSchema.CallToolResult handleListFunctionsSimilarity(Program program, String searchString, int startIndex, int maxCount,
            boolean filterDefaultNames, boolean verbose) {
        if (searchString.trim().isEmpty()) {
            return createErrorResult("search_string cannot be empty");
        }

        String programPath = program.getDomainFile().getPathname();
        SimilarityCacheKey cacheKey = new SimilarityCacheKey(programPath, searchString, filterDefaultNames);
        long currentModNumber = program.getModificationNumber();
        CachedSearchResult cached = similarityCache.get(cacheKey);

        List<Map<String, Object>> sortedFunctions;
        boolean wasCacheHit = false;
        int originalTotalCount = 0;

        if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
            wasCacheHit = true;
            sortedFunctions = cached.sortedFunctions();
            originalTotalCount = cached.totalCount();
        } else {
            List<Map<String, Object>> allFunctions = getOrBuildFunctionInfoCache(program, filterDefaultNames);
            synchronized (similarityCache) {
                cached = similarityCache.get(cacheKey);
                if (cached != null && !cached.isExpired() && cached.programModificationNumber() == currentModNumber) {
                    wasCacheHit = true;
                    sortedFunctions = cached.sortedFunctions();
                    originalTotalCount = cached.totalCount();
                } else {
                    long startTime = System.currentTimeMillis();
                    String searchLower = searchString.toLowerCase();
                    List<Map<String, Object>> substringMatches = new ArrayList<>();
                    List<Map<String, Object>> nonMatches = new ArrayList<>();

                    for (Map<String, Object> functionInfo : allFunctions) {
                        String name = (String) functionInfo.get("name");
                        String nameLower = name.toLowerCase();
                        if (nameLower.contains(searchLower)) {
                            substringMatches.add(functionInfo);
                        } else {
                            nonMatches.add(functionInfo);
                        }
                    }

                    SimilarityComparator<Map<String, Object>> comparator = new SimilarityComparator<>(searchString,
                        new SimilarityComparator.StringExtractor<Map<String, Object>>() {
                            @Override
                            public String extract(Map<String, Object> item) {
                                return (String) item.get("name");
                            }
                        });

                    Collections.sort(substringMatches, comparator);
                    if (substringMatches.size() < 1000 && !nonMatches.isEmpty()) {
                        Collections.sort(nonMatches, comparator);
                    }

                    sortedFunctions = new ArrayList<>(substringMatches.size() + nonMatches.size());
                    sortedFunctions.addAll(substringMatches);
                    sortedFunctions.addAll(nonMatches);
                    originalTotalCount = sortedFunctions.size();

                    List<Map<String, Object>> toCache = sortedFunctions.stream()
                        .limit(MAX_CACHED_RESULTS_PER_SEARCH)
                        .toList();

                    evictExpiredCacheEntries();
                    CachedSearchResult newCached = new CachedSearchResult(toCache, System.currentTimeMillis(),
                        originalTotalCount, currentModNumber);
                    similarityCache.put(cacheKey, newCached);

                    long elapsed = System.currentTimeMillis() - startTime;
                    if (elapsed > SLOW_SEARCH_THRESHOLD_MS) {
                        logInfo("list-functions (similarity): Search for '" + searchString +
                            "' took " + (elapsed / 1000) + "s (" + originalTotalCount + " functions)");
                    }
                }
            }
        }

        int totalCount = sortedFunctions.size();
        List<Map<String, Object>> paginatedFunctionData;
        if (startIndex >= totalCount) {
            paginatedFunctionData = Collections.emptyList();
        } else {
            int endIndex = Math.min(startIndex + maxCount, totalCount);
            paginatedFunctionData = sortedFunctions.subList(startIndex, endIndex);
        }

        String searchLower = searchString.toLowerCase();
        List<Map<String, Object>> transformedResults = new ArrayList<>(paginatedFunctionData.size());
        for (Map<String, Object> funcInfo : paginatedFunctionData) {
            String name = (String) funcInfo.get("name");
            double similarity = SimilarityComparator.calculateLcsSimilarity(searchLower, name.toLowerCase());

            if (verbose) {
                Map<String, Object> fullInfo = new HashMap<>(funcInfo);
                fullInfo.put("similarity", Math.round(similarity * 100.0) / 100.0);
                transformedResults.add(fullInfo);
            } else {
                Map<String, Object> compactInfo = new HashMap<>();
                compactInfo.put("name", name);
                compactInfo.put("address", funcInfo.get("address"));
                compactInfo.put("sizeInBytes", funcInfo.get("sizeInBytes"));
                compactInfo.put("tags", funcInfo.get("tags"));
                compactInfo.put("callerCount", funcInfo.get("callerCount"));
                compactInfo.put("calleeCount", funcInfo.get("calleeCount"));
                compactInfo.put("similarity", Math.round(similarity * 100.0) / 100.0);
                transformedResults.add(compactInfo);
            }
        }

        int reportedTotal = originalTotalCount > 0 ? originalTotalCount : totalCount;
        boolean resultsTruncated = totalCount < reportedTotal;

        Map<String, Object> result = new HashMap<>();
        result.put("matches", transformedResults);
        result.put("search_string", searchString);
        result.put("startIndex", startIndex);
        result.put("requestedCount", maxCount);
        result.put("actualCount", transformedResults.size());
        result.put("nextStartIndex", startIndex + transformedResults.size());
        result.put("totalMatchingFunctions", reportedTotal);
        result.put("filterDefaultNames", filterDefaultNames);
        result.put("verbose", verbose);
        result.put("cacheHit", wasCacheHit);
        if (resultsTruncated) {
            result.put("resultsTruncated", true);
            result.put("maxCachedResults", MAX_CACHED_RESULTS_PER_SEARCH);
        }
        return createJsonResult(result);
    }

    /**
     * Handle list-functions mode='undefined' - undefined function candidates
     */
    private McpSchema.CallToolResult handleListFunctionsUndefined(Program program, int startIndex, int maxCount, int minReferenceCount) {
        FunctionManager funcMgr = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();

        Map<Address, CandidateInfo> candidates = new HashMap<>();
        ReferenceIterator refIter = refMgr.getReferenceIterator(program.getMinAddress());
        Map<MemoryBlock, Boolean> blockExclusionCache = new HashMap<>();

        int refsScanned = 0;
        boolean earlyTermination = false;

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            refsScanned++;

            boolean isCallRef = ref.getReferenceType().isCall();
            boolean isDataRef = ref.getReferenceType().isData();

            if (!isCallRef && !isDataRef) {
                continue;
            }

            Address targetAddr = ref.getToAddress();

            if (funcMgr.getFunctionAt(targetAddr) != null) {
                continue;
            }

            if (targetAddr.isExternalAddress()) {
                continue;
            }

            MemoryBlock block = program.getMemory().getBlock(targetAddr);
            if (block == null || !block.isExecute()) {
                continue;
            }

            Boolean isExcluded = blockExclusionCache.get(block);
            if (isExcluded == null) {
                String blockNameLower = block.getName().toLowerCase();
                isExcluded = EXCLUDED_BLOCK_PATTERNS.stream()
                    .anyMatch(blockNameLower::contains);
                blockExclusionCache.put(block, isExcluded);
            }
            if (isExcluded) {
                continue;
            }

            if (program.getListing().getInstructionAt(targetAddr) == null) {
                continue;
            }

            CandidateInfo info = candidates.computeIfAbsent(targetAddr, k -> new CandidateInfo());
            info.addReference(ref.getFromAddress(), isCallRef, isDataRef);

            if (candidates.size() >= MAX_UNIQUE_CANDIDATES) {
                earlyTermination = true;
                logInfo("list-functions (undefined): Early termination at " +
                    MAX_UNIQUE_CANDIDATES + " unique candidates (memory protection)");
                break;
            }
        }

        List<Map.Entry<Address, CandidateInfo>> sortedCandidates = candidates.entrySet().stream()
            .filter(e -> e.getValue().referenceCount() >= minReferenceCount)
            .sorted((a, b) -> Integer.compare(b.getValue().referenceCount(), a.getValue().referenceCount()))
            .toList();

        int totalCandidates = sortedCandidates.size();
        List<Map<String, Object>> candidatesList = new ArrayList<>();
        int endIndex = Math.min(startIndex + maxCount, sortedCandidates.size());

        for (int i = startIndex; i < endIndex; i++) {
            Map.Entry<Address, CandidateInfo> entry = sortedCandidates.get(i);
            Address addr = entry.getKey();
            CandidateInfo info = entry.getValue();

            Map<String, Object> candidate = new HashMap<>();
            candidate.put("address", AddressUtil.formatAddress(addr));
            candidate.put("referenceCount", info.referenceCount());
            candidate.put("hasCallReference", info.hasCallRef());
            candidate.put("hasDataReference", info.hasDataRef());

            List<String> sampleReferences = new ArrayList<>();
            List<Address> refs = info.references();
            for (int j = 0; j < Math.min(5, refs.size()); j++) {
                Address refAddr = refs.get(j);
                Function refFunc = funcMgr.getFunctionContaining(refAddr);
                if (refFunc != null) {
                    sampleReferences.add(refFunc.getName() + " (" +
                        AddressUtil.formatAddress(refAddr) + ")");
                } else {
                    sampleReferences.add(AddressUtil.formatAddress(refAddr));
                }
            }
            candidate.put("sampleReferences", sampleReferences);

            MemoryBlock block = program.getMemory().getBlock(addr);
            if (block != null) {
                candidate.put("memoryBlock", block.getName());
            }

            Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
            if (symbol != null) {
                candidate.put("existingSymbol", symbol.getName());
            }

            candidatesList.add(candidate);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("candidates", candidatesList);
        result.put("totalCandidates", totalCandidates);
        result.put("referencesScanned", refsScanned);
        if (earlyTermination) {
            result.put("earlyTermination", true);
            result.put("note", "Scan stopped early due to memory limits. Results may be incomplete.");
        }
        result.put("pagination", Map.of(
            "startIndex", startIndex,
            "maxCandidates", maxCount,
            "returnedCount", candidatesList.size(),
            "hasMore", endIndex < totalCandidates
        ));

        return createJsonResult(result);
    }

    /**
     * Register a tool to manage function tags (get/set/add/remove/list).
     */
    private void registerFunctionTagsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("function", Map.of(
            "type", "string",
            "description", "Function name or address (required for get/set/add/remove modes)"
        ));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Operation: 'get' (tags on function), 'set' (replace), 'add', 'remove', 'list' (all tags in program)",
            "enum", List.of("get", "set", "add", "remove", "list")
        ));
        properties.put("tags", Map.of(
            "type", "array",
            "description", "Tag names (required for add; optional for set/remove). Empty/whitespace names are ignored.",
            "items", Map.of("type", "string")
        ));
        properties.put("suggest_tags", SchemaUtil.booleanPropertyWithDefault("When mode='add' or 'set', suggest tags based on function characteristics (API calls, strings, libraries)", false));

        List<String> required = List.of("programPath", "mode");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-function-tags")
            .title("Manage Function Tags")
            .description("Manage function tags. Tags categorize functions (e.g., 'AI', 'rendering'). Use mode='list' for all tags in program.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String mode = getString(request, "mode");
            String programPath = program.getDomainFile().getPathname();

            // Defensive validation - schema enum should catch this, but validates against direct API calls
            if (!VALID_TAG_MODES.contains(mode)) {
                return createErrorResult("Unknown mode: " + mode + ". Valid modes: " + VALID_TAG_MODES);
            }

            // Handle list mode (program-wide, no function needed)
            if ("list".equals(mode)) {
                FunctionTagManager tagManager = program.getFunctionManager().getFunctionTagManager();
                List<? extends FunctionTag> allTags = tagManager.getAllFunctionTags();

                List<Map<String, Object>> tagInfoList = new ArrayList<>();
                for (FunctionTag tag : allTags) {
                    Map<String, Object> tagInfo = new HashMap<>();
                    tagInfo.put("name", tag.getName());
                    tagInfo.put("count", tagManager.getUseCount(tag));
                    String comment = tag.getComment();
                    if (comment != null && !comment.isEmpty()) {
                        tagInfo.put("comment", comment);
                    }
                    tagInfoList.add(tagInfo);
                }

                // Sort by name for consistent output
                tagInfoList.sort(Comparator.comparing(m -> (String) m.get("name")));

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("tags", tagInfoList);
                result.put("totalTags", tagInfoList.size());

                return createJsonResult(result);
            }

            // For all other modes, function is required
            String functionRef = getOptionalString(request, "function", null);
            if (functionRef == null || functionRef.isEmpty()) {
                return createErrorResult("'function' parameter is required for mode: " + mode);
            }

            // Resolve function (throws IllegalArgumentException if not found, caught by registerTool wrapper)
            Function function = getFunctionFromArgs(request.arguments(), program, "function");

            // Handle get mode (no modification)
            if ("get".equals(mode)) {
                List<String> tagNames = function.getTags().stream()
                    .map(FunctionTag::getName)
                    .sorted()
                    .toList();

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("programPath", programPath);
                result.put("mode", mode);
                result.put("function", function.getName());
                result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
                result.put("tags", tagNames);

                return createJsonResult(result);
            }

            // Check if we should suggest tags
            boolean suggestTags = getOptionalBoolean(request, "suggest_tags", false);
            if (suggestTags && ("add".equals(mode) || "set".equals(mode))) {
                return handleSuggestFunctionTags(program, request, function);
            }

            // For set/add/remove, tags parameter handling
            List<String> tagList = getOptionalStringList(request.arguments(), "tags", null);
            if (tagList == null || tagList.isEmpty()) {
                if ("set".equals(mode) || "remove".equals(mode)) {
                    // Empty set clears all tags; empty remove is a no-op
                    tagList = List.of();
                } else {
                    // add mode requires at least one tag
                    return createErrorResult("'tags' parameter is required for mode: " + mode);
                }
            }

            // Modify tags within a transaction
            int txId = program.startTransaction("Update function tags");
            boolean committed = false;
            try {
                if ("set".equals(mode)) {
                    // Copy to HashSet to avoid ConcurrentModificationException when removing
                    Set<FunctionTag> existingTags = new HashSet<>(function.getTags());
                    for (FunctionTag tag : existingTags) {
                        function.removeTag(tag.getName());
                    }
                    for (String tagName : tagList) {
                        if (tagName != null && !tagName.trim().isEmpty()) {
                            function.addTag(tagName.trim());
                        }
                    }
                } else if ("add".equals(mode)) {
                    for (String tagName : tagList) {
                        if (tagName != null && !tagName.trim().isEmpty()) {
                            function.addTag(tagName.trim());
                        }
                    }
                } else if ("remove".equals(mode)) {
                    for (String tagName : tagList) {
                        if (tagName != null && !tagName.trim().isEmpty()) {
                            function.removeTag(tagName.trim());
                        }
                    }
                }

                program.endTransaction(txId, true);
                committed = true;
            } catch (Exception e) {
                if (!committed) {
                    program.endTransaction(txId, false);
                }
                return createErrorResult("Error updating function tags: " + e.getMessage());
            }

            // Auto-save the program to persist changes
            autoSaveProgram(program, "Update function tags");

            // Invalidate caches since tags changed (outside try block for robustness)
            invalidateFunctionCaches(programPath);

            // Return lean response with just identifiers and updated tags
            List<String> updatedTags = function.getTags().stream()
                .map(FunctionTag::getName)
                .sorted()
                .toList();

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("programPath", programPath);
            result.put("mode", mode);
            result.put("function", function.getName());
            result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("tags", updatedTags);

            return createJsonResult(result);
        });
    }

    /**
     * Register the manage-function tool for creating, renaming, and modifying functions and their variables.
     *
     * Variable operations (rename_variable, change_datatypes) require decompiler infrastructure
     * which is included in this provider.
     */
    private void registerManageFunctionTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("action", Map.of(
            "type", "string",
            "description", "Action to perform: 'create' (create function), 'rename_function' (rename function), 'rename_variable' (rename variables), 'set_prototype' (set function prototype), 'set_variable_type' (set single variable type), 'change_datatypes' (change multiple variable data types)",
            "enum", List.of("create", "rename_function", "rename_variable", "set_prototype", "set_variable_type", "change_datatypes")
        ));
        properties.put("address", Map.of(
            "type", "string",
            "description", "Address where the function should be created when action='create' (e.g., '0x401000', required for create)"
        ));
        properties.put("function_identifier", Map.of(
            "type", "string",
            "description", "Function name or address for rename/modify operations (required for rename_function, rename_variable, set_prototype, set_variable_type, change_datatypes)"
        ));
        properties.put("name", Map.of(
            "type", "string",
            "description", "New function name when action='rename_function' or optional name when action='create' (optional, not used in batch mode)"
        ));
        // Batch functions array for renaming multiple functions
        Map<String, Object> functionRenameItemSchema = new HashMap<>();
        functionRenameItemSchema.put("type", "object");
        Map<String, Object> functionRenameItemProperties = new HashMap<>();
        functionRenameItemProperties.put("function_identifier", SchemaUtil.stringProperty("Function name or address to rename"));
        functionRenameItemProperties.put("name", SchemaUtil.stringProperty("New function name"));
        functionRenameItemSchema.put("properties", functionRenameItemProperties);
        functionRenameItemSchema.put("required", List.of("function_identifier", "name"));

        Map<String, Object> functionsArraySchema = new HashMap<>();
        functionsArraySchema.put("type", "array");
        functionsArraySchema.put("description", "Array of function rename objects for batch renaming. Each object should have 'function_identifier' (required) and 'name' (required). When provided with action='rename_function', renames multiple functions in a single transaction.");
        functionsArraySchema.put("items", functionRenameItemSchema);
        properties.put("functions", functionsArraySchema);
        properties.put("old_name", Map.of(
            "type", "string",
            "description", "Old variable name when action='rename_variable' (required for single variable rename)"
        ));
        properties.put("new_name", Map.of(
            "type", "string",
            "description", "New variable name when action='rename_variable' (required for single variable rename)"
        ));
        properties.put("variable_mappings", Map.of(
            "type", "string",
            "description", "Mapping of old to new variable names when action='rename_variable' (format: 'oldName1:newName1,oldName2:newName2', required for multiple variables)"
        ));
        properties.put("prototype", Map.of(
            "type", "string",
            "description", "Function prototype/signature string when action='set_prototype' (required for set_prototype)"
        ));
        properties.put("variable_name", Map.of(
            "type", "string",
            "description", "Variable name when action='set_variable_type' (required for set_variable_type)"
        ));
        properties.put("new_type", Map.of(
            "type", "string",
            "description", "New data type for variable when action='set_variable_type' (required for set_variable_type)"
        ));
        properties.put("datatype_mappings", Map.of(
            "type", "string",
            "description", "Mapping of variable names to new data type strings when action='change_datatypes' (format: 'varName1:type1,varName2:type2', required for change_datatypes)"
        ));
        properties.put("archive_name", Map.of(
            "type", "string",
            "description", "Optional name of the data type archive to search for data types when action='change_datatypes' (optional, default: '')",
            "default", ""
        ));
        properties.put("createIfNotExists", Map.of(
            "type", "boolean",
            "description", "Create function if it doesn't exist when action='set_prototype' (default: true)",
            "default", true
        ));
        properties.put("suggest_name", SchemaUtil.booleanPropertyWithDefault("When action='rename_function', suggest function names based on context (strings, API calls, patterns)", false));

        List<String> required = List.of("programPath", "action");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-function")
            .title("Manage Function")
            .description("Create, rename, or modify functions and their variables.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String action = getString(request, "action");

                switch (action) {
                    case "create":
                        return handleManageFunctionCreate(program, request);
                    case "set_prototype":
                        return handleManageFunctionSetPrototype(program, request);
                    case "rename_variable":
                        return handleManageFunctionRenameVariable(program, request);
                    case "change_datatypes":
                        return handleManageFunctionChangeDatatypes(program, request);
                    case "rename_function":
                        return handleManageFunctionRenameFunction(program, request);
                    case "set_variable_type":
                        return handleManageFunctionSetVariableType(program, request);
                    default:
                        return createErrorResult("Invalid action: " + action + ". Valid actions are: create, rename_function, set_prototype, rename_variable, set_variable_type, change_datatypes");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in manage-function", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    /**
     * Handle manage-function action='create' - create a new function
     */
    private McpSchema.CallToolResult handleManageFunctionCreate(Program program, CallToolRequest request) {
        String programPath = program.getDomainFile().getPathname();
        String name = getOptionalString(request, "name", null);
        Address address = getAddressFromArgs(request, program, "address");

        // Validate address is in executable memory
        MemoryBlock block = program.getMemory().getBlock(address);
        if (block == null) {
            return createErrorResult("Address " + AddressUtil.formatAddress(address) +
                " is not in any memory block");
        }
        if (!block.isExecute()) {
            return createErrorResult("Address " + AddressUtil.formatAddress(address) +
                " is not in executable memory (block: " + block.getName() + ")");
        }

        // Check if there's already a function at this address
        FunctionManager funcMgr = program.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(address);
        if (existingFunc != null) {
            return createErrorResult("Function already exists at " +
                AddressUtil.formatAddress(address) + ": " + existingFunc.getName());
        }

        // Check if there's an instruction at the address
        Instruction instr = program.getListing().getInstructionAt(address);
        if (instr == null) {
            return createErrorResult("No instruction at address " +
                AddressUtil.formatAddress(address) +
                ". The address may need to be disassembled first.");
        }

        // Create the function using CreateFunctionCmd
        int txId = program.startTransaction("Create Function");
        try {
            CreateFunctionCmd cmd = new CreateFunctionCmd(address);
            boolean success = cmd.applyTo(program);

            if (!success) {
                program.endTransaction(txId, false);
                String statusMsg = cmd.getStatusMsg();
                return createErrorResult("Failed to create function at " +
                    AddressUtil.formatAddress(address) +
                    (statusMsg != null ? ": " + statusMsg : ""));
            }

            // Get the created function
            Function createdFunc = funcMgr.getFunctionAt(address);
            if (createdFunc == null) {
                program.endTransaction(txId, false);
                return createErrorResult("Function creation reported success but function not found");
            }

            // Set custom name if provided
            if (name != null && !name.isEmpty()) {
                try {
                    createdFunc.setName(name, SourceType.USER_DEFINED);
                } catch (DuplicateNameException e) {
                    logInfo("manage-function (create): Name '" + name + "' already exists, keeping default name");
                } catch (InvalidInputException e) {
                    logInfo("manage-function (create): Invalid name '" + name + "': " + e.getMessage());
                }
            }

            program.endTransaction(txId, true);

            // Auto-save the program to persist changes
            autoSaveProgram(program, "Create function");

            // Build response
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("programPath", programPath);
            result.put("function", createFunctionInfo(createdFunc, null));
            result.put("address", AddressUtil.formatAddress(address));
            result.put("nameWasProvided", name != null && !name.isEmpty());

            return createJsonResult(result);

        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Error creating function: " + e.getMessage());
        }
    }

    /**
     * Handle manage-function action='set_prototype' - set function prototype
     */
    private McpSchema.CallToolResult handleManageFunctionSetPrototype(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when action='set_prototype'");
        }

        String signature = getString(request, "prototype");
        boolean createIfNotExists = getOptionalBoolean(request, "createIfNotExists", true);

        // Normalize signature to handle whitespace issues
        String normalizedSignature = normalizeFunctionSignature(signature);

        // Resolve the address from function_identifier
        Address address;
        try {
            address = getAddressFromArgs(request, program, "function_identifier");
        } catch (IllegalArgumentException e) {
            return createErrorResult("Invalid address or symbol: " + functionIdentifier + ": " + e.getMessage());
        }

        FunctionManager functionManager = program.getFunctionManager();
        Function existingFunction = functionManager.getFunctionAt(address);

        // Parse the function signature using Ghidra's parser
        FunctionSignatureParser parser = new FunctionSignatureParser(
            program.getDataTypeManager(), null);

        FunctionDefinitionDataType functionDef;
        try {
            // Create original signature from existing function if it exists
            FunctionDefinitionDataType originalSignature = null;
            if (existingFunction != null) {
                originalSignature = new FunctionDefinitionDataType(existingFunction.getName());
                originalSignature.setReturnType(existingFunction.getReturnType());

                // Convert parameters
                List<ParameterDefinition> paramDefs = new ArrayList<>();
                for (Parameter param : existingFunction.getParameters()) {
                    paramDefs.add(new ParameterDefinitionImpl(
                        param.getName(), param.getDataType(), param.getComment()));
                }
                originalSignature.setArguments(paramDefs.toArray(new ParameterDefinition[0]));
                originalSignature.setVarArgs(existingFunction.hasVarArgs());
            }

            functionDef = parser.parse(originalSignature, normalizedSignature);
        } catch (ParseException e) {
            String errorMsg = e.getMessage();
            if (errorMsg != null && errorMsg.contains("Can't resolve datatype")) {
                return createErrorResult("Failed to parse function signature: " + errorMsg +
                    "\n\nHint: The datatype may not be defined in the program. Consider using a basic type (e.g., 'void*' instead of 'FILE*') or import the necessary type definitions.");
            }
            return createErrorResult("Failed to parse function signature: " + errorMsg);
        } catch (CancelledException e) {
            return createErrorResult("Function signature parsing was cancelled");
        }

        int txId = program.startTransaction("Set Function Prototype");
        try {
            Function function = existingFunction;

            // Create function if it doesn't exist and creation is allowed
            if (function == null) {
                if (!createIfNotExists) {
                    return createErrorResult("Function does not exist at " +
                        AddressUtil.formatAddress(address) + " and createIfNotExists is false");
                }

                // Create a new function with minimal body (just the entry point)
                AddressSet body = new AddressSet(address, address);
                function = functionManager.createFunction(
                    functionDef.getName(), address, body, SourceType.USER_DEFINED);

                if (function == null) {
                    return createErrorResult("Failed to create function at " +
                        AddressUtil.formatAddress(address));
                }
            }

            // Check if we need to enable custom storage to modify auto-parameters
            boolean needsCustomStorage = needsCustomStorageForSignature(function, functionDef);
            boolean wasUsingCustomStorage = function.hasCustomVariableStorage();

            if (needsCustomStorage && !wasUsingCustomStorage) {
                function.setCustomVariableStorage(true);
                logInfo("Enabled custom storage for function " + function.getName() +
                        " to allow modifying auto-parameters (e.g., 'this' in __thiscall)");
            }

            // Update function name if it's different
            if (!function.getName().equals(functionDef.getName())) {
                function.setName(functionDef.getName(), SourceType.USER_DEFINED);
            }

            // Convert ParameterDefinitions to Variables
            List<Variable> parameters = new ArrayList<>();
            ParameterDefinition[] paramDefs = functionDef.getArguments();
            Parameter[] existingParams = function.getParameters();

            for (int i = 0; i < paramDefs.length; i++) {
                ParameterDefinition paramDef = paramDefs[i];

                if (function.hasCustomVariableStorage() && i < existingParams.length) {
                    parameters.add(new ParameterImpl(
                        paramDef.getName(),
                        paramDef.getDataType(),
                        existingParams[i].getVariableStorage(),
                        program));
                } else {
                    parameters.add(new ParameterImpl(
                        paramDef.getName(),
                        paramDef.getDataType(),
                        program));
                }
            }

            // Update the function signature
            function.setReturnType(functionDef.getReturnType(), SourceType.USER_DEFINED);

            Function.FunctionUpdateType updateType = function.hasCustomVariableStorage()
                ? Function.FunctionUpdateType.CUSTOM_STORAGE
                : Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;

            function.replaceParameters(parameters, updateType, true, SourceType.USER_DEFINED);

            // Set varargs if needed
            if (functionDef.hasVarArgs() != function.hasVarArgs()) {
                function.setVarArgs(functionDef.hasVarArgs());
            }

            program.endTransaction(txId, true);

            // Auto-save the program to persist changes
            autoSaveProgram(program, "Set function prototype");

            // Return updated function information
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("created", existingFunction == null);
            result.put("function", createFunctionInfo(function, null));
            result.put("address", AddressUtil.formatAddress(address));
            result.put("parsedSignature", functionDef.toString());
            result.put("customStorageEnabled", needsCustomStorage && !wasUsingCustomStorage);
            result.put("usingCustomStorage", function.hasCustomVariableStorage());

            return createJsonResult(result);

        } catch (Exception e) {
            program.endTransaction(txId, false);
            return createErrorResult("Failed to set function prototype: " + e.getMessage());
        }
    }

    /**
     * Handle manage-function action='rename_variable' - rename function variables
     * Requires decompiler infrastructure for variable operations
     */
    private McpSchema.CallToolResult handleManageFunctionRenameVariable(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when action='rename_variable'");
        }

        // Parse variable_mappings string (format: "oldName1:newName1,oldName2:newName2")
        // or use old_name/new_name for single variable
        Map<String, String> mappings = new HashMap<>();
        String variableMappings = getOptionalString(request, "variable_mappings", null);
        String oldName = getOptionalString(request, "old_name", null);
        String newName = getOptionalString(request, "new_name", null);

        if (variableMappings != null && !variableMappings.trim().isEmpty()) {
            // Parse comma-separated key:value pairs
            String[] pairs = variableMappings.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) {
                    mappings.put(kv[0].trim(), kv[1].trim());
                }
            }
        } else if (oldName != null && newName != null) {
            // Single variable rename
            mappings.put(oldName.trim(), newName.trim());
        }

        if (mappings.isEmpty()) {
            return createErrorResult("Either variable_mappings (format: 'oldName1:newName1,oldName2:newName2') or both old_name and new_name are required when action='rename_variable'");
        }

        // Get function
        Function function;
        try {
            Map<String, Object> args = new HashMap<>(request.arguments());
            args.put("functionNameOrAddress", functionIdentifier);
            function = getFunctionFromArgs(args, program);
        } catch (IllegalArgumentException e) {
            if (AddressUtil.isUndefinedFunctionAddress(program, functionIdentifier)) {
                return createErrorResult("Cannot rename variables at " + functionIdentifier +
                    ": this address has code but no defined function. " +
                    "Variable modifications require a defined function. " +
                    "Use action='create' to define it first, then retry the rename.");
            }
            return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName());
        }

        // Read-before-modify validation would go here if we had access to hasReadDecompilation
        // For now, we'll skip it and proceed with the rename

        // Initialize decompiler
        DecompInterface decompiler = createConfiguredDecompilerForFunction(program);
        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }

        String beforeDecompilation = null;
        int renamedCount = 0;

        try {
            // Decompile the function
            TaskMonitor monitor = createTimeoutMonitorForFunction();
            DecompileResults results = decompiler.decompileFunction(function, 0, monitor);

            if (monitor.isCancelled()) {
                return createErrorResult("Decompilation timed out after " + getTimeoutSecondsForFunction() + " seconds");
            }

            if (!results.decompileCompleted()) {
                return createErrorResult("Decompilation failed: " + results.getErrorMessage());
            }

            beforeDecompilation = results.getDecompiledFunction().getC();
            HighFunction highFunction = results.getHighFunction();

            // Process variable mappings
            int transactionId = program.startTransaction("Rename Variables");
            try {
                Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    HighSymbol symbol = symbols.next();
                    String varName = symbol.getName();
                    String newVarName = mappings.get(varName);
                    if (newVarName != null) {
                        HighFunctionDBUtil.updateDBVariable(symbol, newVarName, null, SourceType.USER_DEFINED);
                        logInfo("manage-function (rename_variable): Renamed variable " + varName + " to " + newVarName);
                        renamedCount++;
                    }
                }

                program.endTransaction(transactionId, true);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                logError("manage-function (rename_variable): Error during variable renaming", e);
                return createErrorResult("Failed to rename variables: " + e.getMessage());
            }
        } finally {
            decompiler.dispose();
        }

        if (renamedCount == 0) {
            return createErrorResult("No matching variables found to rename");
        }

        // Auto-save the program to persist changes
        autoSaveProgram(program, "Rename variables");

        // Build result
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("programName", program.getName());
        resultData.put("functionName", function.getName());
        resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        resultData.put("variablesRenamed", true);
        resultData.put("renamedCount", renamedCount);

        // Get updated decompilation and create diff
        try {
            DecompInterface diffDecompiler = createConfiguredDecompilerForFunction(program);
            try {
                TaskMonitor monitor = createTimeoutMonitorForFunction();
                DecompileResults results = diffDecompiler.decompileFunction(function, 0, monitor);
                if (results.decompileCompleted()) {
                    String afterDecompilation = results.getDecompiledFunction().getC();
                    resultData.putAll(DecompilationDiffUtil.toMap(DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation)));
                }
            } finally {
                diffDecompiler.dispose();
            }
        } catch (Exception e) {
            logError("manage-function (rename_variable): Error creating decompilation diff", e);
        }

        return createJsonResult(resultData);
    }

    /**
     * Handle manage-function action='change_datatypes' - change variable data types
     */
    private McpSchema.CallToolResult handleManageFunctionChangeDatatypes(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when action='change_datatypes'");
        }

        // Parse datatype_mappings string (format: "varName1:type1,varName2:type2")
        String datatypeMappings = getString(request, "datatype_mappings");
        String archiveName = getOptionalString(request, "archive_name", "");

        Map<String, String> mappings = new HashMap<>();
        if (datatypeMappings != null && !datatypeMappings.trim().isEmpty()) {
            String[] pairs = datatypeMappings.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) {
                    mappings.put(kv[0].trim(), kv[1].trim());
                }
            }
        }

        if (mappings.isEmpty()) {
            return createErrorResult("datatype_mappings (format: 'varName1:type1,varName2:type2') is required when action='change_datatypes'");
        }

        // Get function
        Function function;
        try {
            Map<String, Object> args = new HashMap<>(request.arguments());
            args.put("functionNameOrAddress", functionIdentifier);
            function = getFunctionFromArgs(args, program);
        } catch (IllegalArgumentException e) {
            if (AddressUtil.isUndefinedFunctionAddress(program, functionIdentifier)) {
                return createErrorResult("Cannot change variable datatypes at " + functionIdentifier +
                    ": this address has code but no defined function. " +
                    "Variable modifications require a defined function. " +
                    "Use action='create' to define it first, then retry the datatype change.");
            }
            return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName());
        }

        // Initialize decompiler
        DecompInterface decompiler = createConfiguredDecompilerForFunction(program);
        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }

        String beforeDecompilation = null;
        List<String> errors = new ArrayList<>();
        int changedCount = 0;

        try {
            // Decompile the function
            TaskMonitor monitor = createTimeoutMonitorForFunction();
            DecompileResults results = decompiler.decompileFunction(function, 0, monitor);

            if (monitor.isCancelled()) {
                return createErrorResult("Decompilation timed out after " + getTimeoutSecondsForFunction() + " seconds");
            }

            if (!results.decompileCompleted()) {
                return createErrorResult("Decompilation failed: " + results.getErrorMessage());
            }

            beforeDecompilation = results.getDecompiledFunction().getC();
            HighFunction highFunction = results.getHighFunction();

            // Process variable data type changes
            int transactionId = program.startTransaction("Change Variable Data Types");
            boolean transactionSuccess = false;
            try {
                Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    HighSymbol symbol = symbols.next();
                    String varName = symbol.getName();
                    String typeString = mappings.get(varName);
                    if (typeString != null) {
                        try {
                            DataType newType = DataTypeParserUtil.parseDataTypeObjectFromString(
                                typeString, archiveName);
                            HighFunctionDBUtil.updateDBVariable(symbol, null, newType, SourceType.USER_DEFINED);
                            logInfo("manage-function (change_datatypes): Changed variable " + varName + " type to " + newType);
                            changedCount++;
                        } catch (Exception e) {
                            errors.add("Failed to change type of variable '" + varName + "': " + e.getMessage());
                        }
                    }
                }

                transactionSuccess = true;
            } catch (Exception e) {
                logError("manage-function (change_datatypes): Error during variable data type changes", e);
                return createErrorResult("Failed to change variable data types: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, transactionSuccess);
            }
        } finally {
            decompiler.dispose();
        }

        if (changedCount == 0 && errors.isEmpty()) {
            return createErrorResult("No matching variables found to change data types");
        }

        // Auto-save the program to persist changes
        autoSaveProgram(program, "Change variable data types");

        // Build result
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("programName", program.getName());
        resultData.put("functionName", function.getName());
        resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        resultData.put("dataTypesChanged", changedCount > 0);
        resultData.put("changedCount", changedCount);

        if (!errors.isEmpty()) {
            resultData.put("errors", errors);
        }

        // Get updated decompilation and create diff
        try {
            DecompInterface diffDecompiler = createConfiguredDecompilerForFunction(program);
            try {
                TaskMonitor monitor = createTimeoutMonitorForFunction();
                DecompileResults results = diffDecompiler.decompileFunction(function, 0, monitor);
                if (results.decompileCompleted()) {
                    String afterDecompilation = results.getDecompiledFunction().getC();
                    resultData.putAll(DecompilationDiffUtil.toMap(DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation)));
                }
            } finally {
                diffDecompiler.dispose();
            }
        } catch (Exception e) {
            logError("manage-function (change_datatypes): Error creating decompilation diff", e);
        }

        return createJsonResult(resultData);
    }

    // Helper methods for decompiler operations (needed for variable operations)

    private DecompInterface createConfiguredDecompilerForFunction(Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            logError("Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    private TaskMonitor createTimeoutMonitorForFunction() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = configManager != null ? configManager.getDecompilerTimeoutSeconds() : 60;
        return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
    }

    private int getTimeoutSecondsForFunction() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        return configManager != null ? configManager.getDecompilerTimeoutSeconds() : 60;
    }

    /**
     * Handle manage-function action='rename_function' - rename a function
     */
    private McpSchema.CallToolResult handleManageFunctionRenameFunction(Program program, CallToolRequest request) {
        // Check for batch mode (functions array)
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> functionsArray = getOptionalFunctionsArray(request);
        
        if (functionsArray != null && !functionsArray.isEmpty()) {
            return handleBatchRenameFunctions(program, request, functionsArray);
        }

        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when action='rename_function' (or use 'functions' array for batch mode)");
        }

        // Check if we should suggest names
        boolean suggestName = getOptionalBoolean(request, "suggest_name", false);
        if (suggestName) {
            return handleSuggestFunctionName(program, request, functionIdentifier);
        }

        String newName = getOptionalString(request, "name", null);
        if (newName == null || newName.trim().isEmpty()) {
            return createErrorResult("name is required when action='rename_function' (or use suggest_name=true for suggestions)");
        }

        // Get function
        Function function;
        try {
            Map<String, Object> args = new HashMap<>(request.arguments());
            args.put("functionNameOrAddress", functionIdentifier);
            function = getFunctionFromArgs(args, program);
        } catch (IllegalArgumentException e) {
            return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName());
        }

        String oldName = function.getName();
        if (oldName.equals(newName)) {
            return createErrorResult("Function already has name: " + newName);
        }

        // Rename the function
        int txId = program.startTransaction("Rename Function");
        try {
            function.setName(newName.trim(), SourceType.USER_DEFINED);
            program.endTransaction(txId, true);
        } catch (DuplicateNameException e) {
            program.endTransaction(txId, false);
            return createErrorResult("Function name '" + newName + "' already exists in program");
        } catch (InvalidInputException e) {
            program.endTransaction(txId, false);
            return createErrorResult("Invalid function name '" + newName + "': " + e.getMessage());
        } catch (Exception e) {
            program.endTransaction(txId, false);
            logError("manage-function (rename_function): Error renaming function", e);
            return createErrorResult("Failed to rename function: " + e.getMessage());
        }

        // Auto-save the program to persist changes
        autoSaveProgram(program, "Rename function");

        // Invalidate function caches since name changed
        invalidateFunctionCaches(program.getDomainFile().getPathname());

        // Build result
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("oldName", oldName);
        result.put("newName", newName.trim());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("function", createFunctionInfo(function, null));

        return createJsonResult(result);
    }

    /**
     * Handle suggest function name action
     */
    private McpSchema.CallToolResult handleSuggestFunctionName(Program program, CallToolRequest request, String functionIdentifier) {
        // Get function
        Function function;
        try {
            Map<String, Object> args = new HashMap<>(request.arguments());
            args.put("functionNameOrAddress", functionIdentifier);
            function = getFunctionFromArgs(args, program);
        } catch (IllegalArgumentException e) {
            return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName());
        }

        List<Map<String, Object>> suggestions = SmartSuggestionsUtil.suggestFunctionNames(program, function);
        
        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("function", functionIdentifier);
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("currentName", function.getName());
        result.put("suggestions", suggestions);
        
        return createJsonResult(result);
    }

    /**
     * Get optional functions array from request for batch operations
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getOptionalFunctionsArray(CallToolRequest request) {
        Object value = request.arguments().get("functions");
        if (value == null) {
            return null;
        }
        if (value instanceof List) {
            return (List<Map<String, Object>>) value;
        }
        throw new IllegalArgumentException("Parameter 'functions' must be an array");
    }

    /**
     * Handle batch renaming of multiple functions in a single transaction
     */
    private McpSchema.CallToolResult handleBatchRenameFunctions(Program program,
            CallToolRequest request,
            List<Map<String, Object>> functionsArray) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        try {
            int transactionId = program.startTransaction("Batch Rename Functions");
            try {
                for (int i = 0; i < functionsArray.size(); i++) {
                    Map<String, Object> functionObj = functionsArray.get(i);

                    // Extract function identifier
                    Object funcIdObj = functionObj.get("function_identifier");
                    if (funcIdObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'function_identifier' field in function object"));
                        continue;
                    }
                    String functionIdentifier = funcIdObj.toString();

                    // Extract new name
                    Object nameObj = functionObj.get("name");
                    if (nameObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'name' field in function object"));
                        continue;
                    }
                    String newName = nameObj.toString().trim();

                    if (newName.isEmpty()) {
                        errors.add(createErrorInfo(i, "Function name cannot be empty"));
                        continue;
                    }

                    // Get function
                    Function function;
                    try {
                        Map<String, Object> args = new HashMap<>();
                        args.put("functionNameOrAddress", functionIdentifier);
                        function = getFunctionFromArgs(args, program);
                    } catch (IllegalArgumentException e) {
                        errors.add(createErrorInfo(i, "Function not found: " + functionIdentifier + " - " + e.getMessage()));
                        continue;
                    }

                    String oldName = function.getName();
                    if (oldName.equals(newName)) {
                        errors.add(createErrorInfo(i, "Function already has name: " + newName));
                        continue;
                    }

                    // Rename the function
                    try {
                        function.setName(newName, SourceType.USER_DEFINED);

                        // Record success
                        Map<String, Object> result = new HashMap<>();
                        result.put("index", i);
                        result.put("oldName", oldName);
                        result.put("newName", newName);
                        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
                        results.add(result);
                    } catch (DuplicateNameException e) {
                        errors.add(createErrorInfo(i, "Function name '" + newName + "' already exists in program"));
                    } catch (InvalidInputException e) {
                        errors.add(createErrorInfo(i, "Invalid function name '" + newName + "': " + e.getMessage()));
                    } catch (Exception e) {
                        errors.add(createErrorInfo(i, "Failed to rename function: " + e.getMessage()));
                    }
                }

                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Batch rename functions");

                // Invalidate function caches since names changed
                invalidateFunctionCaches(program.getDomainFile().getPathname());

                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("programPath", program.getDomainFile().getPathname());
                response.put("total", functionsArray.size());
                response.put("succeeded", results.size());
                response.put("failed", errors.size());
                response.put("results", results);
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                }

                return createJsonResult(response);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error in batch rename functions", e);
            return createErrorResult("Failed to batch rename functions: " + e.getMessage());
        }
    }

    /**
     * Handle suggest function tags action
     */
    private McpSchema.CallToolResult handleSuggestFunctionTags(Program program, CallToolRequest request, Function function) {
        List<Map<String, Object>> suggestions = SmartSuggestionsUtil.suggestFunctionTags(program, function);
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("function", function.getName());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("currentTags", function.getTags().stream().map(FunctionTag::getName).sorted().toList());
        result.put("suggestions", suggestions);
        
        return createJsonResult(result);
    }

    /**
     * Create error info for batch operations
     */
    private Map<String, Object> createErrorInfo(int index, String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("index", index);
        error.put("error", message);
        return error;
    }

    /**
     * Handle manage-function action='set_variable_type' - set a single variable's data type
     */
    private McpSchema.CallToolResult handleManageFunctionSetVariableType(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when action='set_variable_type'");
        }

        String variableName = getOptionalString(request, "variable_name", null);
        if (variableName == null || variableName.trim().isEmpty()) {
            return createErrorResult("variable_name is required when action='set_variable_type'");
        }

        String newType = getOptionalString(request, "new_type", null);
        if (newType == null || newType.trim().isEmpty()) {
            return createErrorResult("new_type is required when action='set_variable_type'");
        }

        String archiveName = getOptionalString(request, "archive_name", "");

        // Get function
        Function function;
        try {
            Map<String, Object> args = new HashMap<>(request.arguments());
            args.put("functionNameOrAddress", functionIdentifier);
            function = getFunctionFromArgs(args, program);
        } catch (IllegalArgumentException e) {
            if (AddressUtil.isUndefinedFunctionAddress(program, functionIdentifier)) {
                return createErrorResult("Cannot change variable type at " + functionIdentifier +
                    ": this address has code but no defined function. " +
                    "Variable modifications require a defined function. " +
                    "Use action='create' to define it first, then retry the type change.");
            }
            return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName());
        }

        // Initialize decompiler
        DecompInterface decompiler = createConfiguredDecompilerForFunction(program);
        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }

        String beforeDecompilation = null;
        boolean typeChanged = false;

        try {
            // Decompile the function
            TaskMonitor monitor = createTimeoutMonitorForFunction();
            DecompileResults results = decompiler.decompileFunction(function, 0, monitor);

            if (monitor.isCancelled()) {
                return createErrorResult("Decompilation timed out after " + getTimeoutSecondsForFunction() + " seconds");
            }

            if (!results.decompileCompleted()) {
                return createErrorResult("Decompilation failed: " + results.getErrorMessage());
            }

            beforeDecompilation = results.getDecompiledFunction().getC();
            HighFunction highFunction = results.getHighFunction();

            // Find and update the variable
            int transactionId = program.startTransaction("Set Variable Type");
            boolean transactionSuccess = false;
            try {
                Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    HighSymbol symbol = symbols.next();
                    if (variableName.equals(symbol.getName())) {
                        try {
                            DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
                                newType, archiveName);
                            HighFunctionDBUtil.updateDBVariable(symbol, null, newDataType, SourceType.USER_DEFINED);
                            logInfo("manage-function (set_variable_type): Changed variable " + variableName + " type to " + newDataType);
                            typeChanged = true;
                            break;
                        } catch (Exception e) {
                            program.endTransaction(transactionId, false);
                            return createErrorResult("Failed to parse data type '" + newType + "': " + e.getMessage());
                        }
                    }
                }

                if (!typeChanged) {
                    program.endTransaction(transactionId, false);
                    return createErrorResult("Variable '" + variableName + "' not found in function '" + function.getName() + "'");
                }

                transactionSuccess = true;
            } catch (Exception e) {
                logError("manage-function (set_variable_type): Error during variable type change", e);
                return createErrorResult("Failed to change variable type: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, transactionSuccess);
            }
        } finally {
            decompiler.dispose();
        }

        // Auto-save the program to persist changes
        autoSaveProgram(program, "Set variable type");

        // Build result
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("programName", program.getName());
        resultData.put("functionName", function.getName());
        resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        resultData.put("variableName", variableName);
        resultData.put("newType", newType);
        resultData.put("typeChanged", true);

        // Get updated decompilation and create diff
        try {
            DecompInterface diffDecompiler = createConfiguredDecompilerForFunction(program);
            try {
                TaskMonitor monitor = createTimeoutMonitorForFunction();
                DecompileResults results = diffDecompiler.decompileFunction(function, 0, monitor);
                if (results.decompileCompleted()) {
                    String afterDecompilation = results.getDecompiledFunction().getC();
                    resultData.putAll(DecompilationDiffUtil.toMap(DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation)));
                }
            } finally {
                diffDecompiler.dispose();
            }
        } catch (Exception e) {
            logError("manage-function (set_variable_type): Error creating decompilation diff", e);
        }

        return createJsonResult(resultData);
    }

}
