package reva.tools.callgraph;

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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DecompilationReadTracker;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for call graph analysis operations.
 * Provides tools for analyzing function call relationships and hierarchies.
 *
 * <p>Uses Ghidra's built-in Function.getCallingFunctions() and
 * Function.getCalledFunctions() for accurate call relationship detection.</p>
 */
public class CallGraphToolProvider extends AbstractToolProvider {

    private static final int DEFAULT_MAX_DEPTH = 3;
    private static final int MAX_DEPTH_LIMIT = 10;
    /** Max nodes per direction (callers or callees) for graph view */
    private static final int MAX_NODES_PER_DIRECTION = 250;
    /** Max nodes for tree view - higher because tree allows same function in different branches */
    private static final int MAX_NODES_TREE = 500;
    private static final int DEFAULT_TIMEOUT_SECONDS = 60;

    public CallGraphToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerGetCallGraphTool();
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

    // ========================================================================
    // Tool Registration
    // ========================================================================

    /**
     * Register the get-call-graph tool
     */
    private void registerGetCallGraphTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("function_identifier", Map.of(
            "type", "string",
            "description", "Function name or address (required for all modes except common_callers)"
        ));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Analysis mode: 'graph' (bidirectional call graph), 'tree' (hierarchical tree), 'callers' (list of callers), 'callees' (list of callees), 'callers_decomp' (decompiled callers), 'common_callers' (functions that call all specified functions)",
            "enum", List.of("graph", "tree", "callers", "callees", "callers_decomp", "common_callers"),
            "default", "graph"
        ));
        properties.put("depth", Map.of(
            "type", "integer",
            "description", "Depth of call graph to retrieve when mode='graph' (default: 1, max: 10)",
            "default", 1
        ));
        properties.put("direction", Map.of(
            "type", "string",
            "description", "Direction to traverse when mode='tree', 'callers', or 'callees': 'callers' or 'callees' (default: 'callees' for tree)",
            "enum", List.of("callers", "callees"),
            "default", "callees"
        ));
        properties.put("max_depth", Map.of(
            "type", "integer",
            "description", "Maximum depth to traverse when mode='tree' (default: 3, max: 10)",
            "default", 3
        ));
        properties.put("start_index", Map.of(
            "type", "integer",
            "description", "Starting index for pagination when mode='callers_decomp' (0-based, default: 0)",
            "default", 0
        ));
        properties.put("max_callers", Map.of(
            "type", "integer",
            "description", "Maximum number of calling functions to decompile when mode='callers_decomp' (default: 10, max: 50)",
            "default", 10
        ));
        properties.put("include_call_context", Map.of(
            "type", "boolean",
            "description", "Whether to highlight the line containing the call in each decompilation when mode='callers_decomp' (default: true)",
            "default", true
        ));
        properties.put("function_addresses", Map.of(
            "type", "string",
            "description", "Comma-separated list of function addresses or names when mode='common_callers' (required for common_callers mode, format: 'func1,func2,func3')"
        ));

        List<String> required = List.of("programPath");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-call-graph")
            .title("Get Call Graph")
            .description("Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees, caller/callee lists, decompiled callers, or common callers.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String mode = getOptionalString(request, "mode", "graph");

                switch (mode) {
                    case "graph":
                        return handleGetCallGraphMode(program, request);
                    case "tree":
                        return handleGetCallTreeMode(program, request);
                    case "callers":
                        return handleGetCallersMode(program, request);
                    case "callees":
                        return handleGetCalleesMode(program, request);
                    case "callers_decomp":
                        return handleGetCallersDecompiledMode(program, request);
                    case "common_callers":
                        return handleFindCommonCallersMode(program, request);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: graph, tree, callers, callees, callers_decomp, common_callers");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in get-call-graph", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    // ========================================================================
    // Core Analysis Methods
    // ========================================================================

    private McpSchema.CallToolResult getCallGraph(Program program, Function centerFunction, int depth) {
        TaskMonitor monitor = createTimeoutMonitor();

        // Use separate counters for each direction
        int[] callerNodeCount = {0};
        int[] calleeNodeCount = {0};

        // Build caller graph (upward) with its own visited set and counter
        Set<String> callerVisited = new HashSet<>();
        List<Map<String, Object>> callers;
        try {
            callers = buildGraphList(centerFunction, depth, callerVisited,
                callerNodeCount, true, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        // Build callee graph (downward) with its own visited set and counter
        Set<String> calleeVisited = new HashSet<>();
        List<Map<String, Object>> callees;
        try {
            callees = buildGraphList(centerFunction, depth, calleeVisited,
                calleeNodeCount, false, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("centerFunction", Map.of(
            "name", centerFunction.getName(),
            "address", AddressUtil.formatAddress(centerFunction.getEntryPoint())
        ));
        result.put("depth", depth);
        result.put("callerCount", callerNodeCount[0]);
        result.put("calleeCount", calleeNodeCount[0]);
        result.put("callers", callers);
        result.put("callees", callees);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult getCallTree(Program program, Function rootFunction,
            int maxDepth, boolean traverseCallers) {

        TaskMonitor monitor = createTimeoutMonitor();
        Set<String> visited = new HashSet<>();
        int[] nodeCount = {0};

        Map<String, Object> tree;
        try {
            tree = buildTree(rootFunction, maxDepth, 0, visited,
                nodeCount, traverseCallers, monitor);
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("direction", traverseCallers ? "callers" : "callees");
        result.put("maxDepth", maxDepth);
        result.put("totalNodes", nodeCount[0]);
        result.put("tree", tree);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult findCommonCallers(Program program, List<Function> targetFunctions) {
        TaskMonitor monitor = createTimeoutMonitor();
        Set<Function> commonCallers = null;

        try {
            for (Function targetFunc : targetFunctions) {
                monitor.checkCancelled();

                Set<Function> callersOfThis = targetFunc.getCallingFunctions(monitor);

                if (commonCallers == null) {
                    commonCallers = new HashSet<>(callersOfThis);
                } else {
                    commonCallers.retainAll(callersOfThis);
                }

                // Early exit if no common callers remain
                if (commonCallers.isEmpty()) {
                    break;
                }
            }
        } catch (CancelledException e) {
            return createErrorResult("Operation cancelled or timed out");
        }

        List<Map<String, Object>> callerList = new ArrayList<>();
        if (commonCallers != null) {
            for (Function caller : commonCallers) {
                Map<String, Object> callerInfo = new HashMap<>();
                callerInfo.put("name", caller.getName());
                callerInfo.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
                callerList.add(callerInfo);
            }
        }

        // Sort by address - use entry point directly for reliable comparison
        callerList.sort((a, b) -> {
            String addrStrA = (String) a.get("address");
            String addrStrB = (String) b.get("address");
            if (addrStrA == null && addrStrB == null) return 0;
            if (addrStrA == null) return 1;  // Nulls sort to end
            if (addrStrB == null) return -1;
            // Compare hex strings (both have 0x prefix from AddressUtil)
            return addrStrA.compareTo(addrStrB);
        });

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("targetFunctions", targetFunctions.stream()
            .map(f -> Map.of(
                "name", f.getName(),
                "address", AddressUtil.formatAddress(f.getEntryPoint())
            ))
            .toList());
        result.put("commonCallerCount", callerList.size());
        result.put("commonCallers", callerList);

        return createJsonResult(result);
    }

    // ========================================================================
    // Graph/Tree Building Methods
    // ========================================================================

    /**
     * Build a list of callers or callees for the graph view.
     * Uses permanent visited tracking to avoid duplicates across branches.
     */
    private List<Map<String, Object>> buildGraphList(Function function,
            int depth, Set<String> visited, int[] nodeCount, boolean getCallers,
            TaskMonitor monitor) throws CancelledException {

        if (depth <= 0 || nodeCount[0] >= MAX_NODES_PER_DIRECTION) {
            return List.of();
        }

        monitor.checkCancelled();

        List<Map<String, Object>> results = new ArrayList<>();
        Set<Function> related = getCallers
            ? function.getCallingFunctions(monitor)
            : function.getCalledFunctions(monitor);

        for (Function relatedFunc : related) {
            if (nodeCount[0] >= MAX_NODES_PER_DIRECTION) break;
            monitor.checkCancelled();

            String funcKey = getFunctionKey(relatedFunc);
            boolean isCycle = visited.contains(funcKey);

            Map<String, Object> info = new HashMap<>();
            info.put("name", relatedFunc.getName());
            info.put("address", AddressUtil.formatAddress(relatedFunc.getEntryPoint()));

            if (isCycle) {
                info.put("cyclic", true);
            } else {
                visited.add(funcKey);
                nodeCount[0]++;

                if (depth > 1) {
                    List<Map<String, Object>> nested = buildGraphList(relatedFunc,
                        depth - 1, visited, nodeCount, getCallers, monitor);
                    if (!nested.isEmpty()) {
                        info.put(getCallers ? "callers" : "callees", nested);
                    }
                }
            }

            results.add(info);
        }

        return results;
    }

    /**
     * Build a tree structure for the tree view.
     * Uses temporary visited tracking (removes after recursion) to allow
     * the same function to appear in different branches while detecting cycles.
     */
    private Map<String, Object> buildTree(Function function,
            int maxDepth, int currentDepth, Set<String> visited, int[] nodeCount,
            boolean getCallers, TaskMonitor monitor) throws CancelledException {

        monitor.checkCancelled();

        Map<String, Object> node = new HashMap<>();
        node.put("name", function.getName());
        node.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        node.put("depth", currentDepth);

        String funcKey = getFunctionKey(function);

        // Cycle detection within current path
        if (visited.contains(funcKey)) {
            node.put("cyclic", true);
            return node;
        }

        // Depth or node limit reached
        if (currentDepth >= maxDepth || nodeCount[0] >= MAX_NODES_TREE) {
            if (currentDepth >= maxDepth) {
                node.put("truncated", true);
            }
            return node;
        }

        // Mark as visited for this path
        visited.add(funcKey);
        nodeCount[0]++;

        Set<Function> related = getCallers
            ? function.getCallingFunctions(monitor)
            : function.getCalledFunctions(monitor);

        if (!related.isEmpty()) {
            List<Map<String, Object>> childNodes = new ArrayList<>();
            for (Function relatedFunc : related) {
                if (nodeCount[0] >= MAX_NODES_TREE) break;
                monitor.checkCancelled();

                childNodes.add(buildTree(relatedFunc, maxDepth,
                    currentDepth + 1, visited, nodeCount, getCallers, monitor));
            }
            node.put(getCallers ? "callers" : "callees", childNodes);
        }

        // Remove from visited to allow this function in other branches
        visited.remove(funcKey);
        return node;
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Resolve a function at or containing the given address.
     */
    private Function resolveFunction(Program program, Address address) {
        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            function = program.getFunctionManager().getFunctionContaining(address);
        }
        return function;
    }

    /**
     * Clamp depth to valid range.
     */
    private int clampDepth(int depth) {
        if (depth < 1) return 1;
        if (depth > MAX_DEPTH_LIMIT) return MAX_DEPTH_LIMIT;
        return depth;
    }

    /**
     * Create a unique key for a function using its entry point address.
     */
    private String getFunctionKey(Function function) {
        return AddressUtil.formatAddress(function.getEntryPoint());
    }

    /**
     * Create a timeout monitor for long-running operations.
     */
    private TaskMonitor createTimeoutMonitor() {
        return TimeoutTaskMonitor.timeoutIn(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    // ========================================================================
    // Tool Mode Handlers
    // ========================================================================

    /**
     * Handle get-call-graph mode='graph' - bidirectional call graph
     */
    private McpSchema.CallToolResult handleGetCallGraphMode(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when mode='graph'");
        }

        Address address = getAddressFromArgs(request, program, "function_identifier");
        int depth = getOptionalInt(request, "depth", 1);
        depth = clampDepth(depth);

        Function function = resolveFunction(program, address);
        if (function == null) {
            return createErrorResult("No function at address: " + AddressUtil.formatAddress(address));
        }

        return getCallGraph(program, function, depth);
    }

    /**
     * Handle get-call-graph mode='tree' - hierarchical call tree
     */
    private McpSchema.CallToolResult handleGetCallTreeMode(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when mode='tree'");
        }

        Address address = getAddressFromArgs(request, program, "function_identifier");
        String direction = getOptionalString(request, "direction", "callees");
        int maxDepth = getOptionalInt(request, "max_depth", DEFAULT_MAX_DEPTH);

        if (!"callers".equalsIgnoreCase(direction) && !"callees".equalsIgnoreCase(direction)) {
            return createErrorResult("Invalid direction: '" + direction + "'. Must be 'callers' or 'callees'.");
        }

        maxDepth = clampDepth(maxDepth);

        Function function = resolveFunction(program, address);
        if (function == null) {
            return createErrorResult("No function at address: " + AddressUtil.formatAddress(address));
        }

        boolean traverseCallers = "callers".equalsIgnoreCase(direction);
        return getCallTree(program, function, maxDepth, traverseCallers);
    }

    /**
     * Handle get-call-graph mode='callers' - list of callers
     */
    private McpSchema.CallToolResult handleGetCallersMode(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when mode='callers'");
        }

        Address address = getAddressFromArgs(request, program, "function_identifier");
        String direction = getOptionalString(request, "direction", "callers");

        // For callers mode, direction must be 'callers'
        if (!"callers".equalsIgnoreCase(direction)) {
            return createErrorResult("When mode='callers', direction must be 'callers'");
        }

        Function function = resolveFunction(program, address);
        if (function == null) {
            return createErrorResult("No function at address: " + AddressUtil.formatAddress(address));
        }

        TaskMonitor monitor = createTimeoutMonitor();
        Set<Function> callers = function.getCallingFunctions(monitor);

        List<Map<String, Object>> callerList = new ArrayList<>();
        for (Function caller : callers) {
            Map<String, Object> callerInfo = new HashMap<>();
            callerInfo.put("name", caller.getName());
            callerInfo.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
            callerList.add(callerInfo);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("targetFunction", Map.of(
            "name", function.getName(),
            "address", AddressUtil.formatAddress(function.getEntryPoint())
        ));
        result.put("callerCount", callerList.size());
        result.put("callers", callerList);

        return createJsonResult(result);
    }

    /**
     * Handle get-call-graph mode='callees' - list of callees
     */
    private McpSchema.CallToolResult handleGetCalleesMode(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when mode='callees'");
        }

        Address address = getAddressFromArgs(request, program, "function_identifier");
        String direction = getOptionalString(request, "direction", "callees");

        // For callees mode, direction must be 'callees'
        if (!"callees".equalsIgnoreCase(direction)) {
            return createErrorResult("When mode='callees', direction must be 'callees'");
        }

        Function function = resolveFunction(program, address);
        if (function == null) {
            return createErrorResult("No function at address: " + AddressUtil.formatAddress(address));
        }

        TaskMonitor monitor = createTimeoutMonitor();
        Set<Function> callees = function.getCalledFunctions(monitor);

        List<Map<String, Object>> calleeList = new ArrayList<>();
        for (Function callee : callees) {
            Map<String, Object> calleeInfo = new HashMap<>();
            calleeInfo.put("name", callee.getName());
            calleeInfo.put("address", AddressUtil.formatAddress(callee.getEntryPoint()));
            calleeList.add(calleeInfo);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("programPath", program.getDomainFile().getPathname());
        result.put("targetFunction", Map.of(
            "name", function.getName(),
            "address", AddressUtil.formatAddress(function.getEntryPoint())
        ));
        result.put("calleeCount", calleeList.size());
        result.put("callees", calleeList);

        return createJsonResult(result);
    }

    /**
     * Handle get-call-graph mode='callers_decomp' - decompiled callers
     */
    private McpSchema.CallToolResult handleGetCallersDecompiledMode(Program program, CallToolRequest request) {
        String functionIdentifier = getOptionalString(request, "function_identifier", null);
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return createErrorResult("function_identifier is required when mode='callers_decomp'");
        }

        int maxCallers = getOptionalInt(request, "max_callers", 10);
        int startIndex = getOptionalInt(request, "start_index", 0);
        boolean includeCallContext = getOptionalBoolean(request, "include_call_context", true);

        // Validate parameters
        if (maxCallers <= 0 || maxCallers > 50) {
            return createErrorResult("max_callers must be between 1 and 50");
        }
        if (startIndex < 0) {
            return createErrorResult("start_index must be non-negative");
        }

        // Resolve the target function
        Function targetFunction;
        try {
            Map<String, Object> args = new HashMap<>(request.arguments());
            args.put("functionNameOrAddress", functionIdentifier);
            targetFunction = getFunctionFromArgs(args, program);
        } catch (IllegalArgumentException e) {
            return createErrorResult("Function not found: " + e.getMessage() + " in program " + program.getName());
        }

        // Get all references to this function
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refIter = refManager.getReferencesTo(targetFunction.getEntryPoint());

        // Collect unique calling functions
        final int MAX_TOTAL_CALLERS = 500;
        Set<Function> callingFunctions = new HashSet<>();
        Map<Function, List<Address>> callSites = new HashMap<>();

        while (refIter.hasNext() && callingFunctions.size() < MAX_TOTAL_CALLERS) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall() || ref.getReferenceType().isFlow()) {
                Address fromAddr = ref.getFromAddress();
                Function caller = program.getFunctionManager().getFunctionContaining(fromAddr);
                if (caller != null && !caller.equals(targetFunction)) {
                    callingFunctions.add(caller);
                    callSites.computeIfAbsent(caller, k -> new ArrayList<>()).add(fromAddr);
                }
            }
        }

        // Convert to list for pagination
        List<Function> callerList = new ArrayList<>(callingFunctions);
        int totalCallers = callerList.size();

        // Apply pagination
        int endIndex = Math.min(startIndex + maxCallers, totalCallers);
        List<Function> pageCallers = startIndex < totalCallers
            ? callerList.subList(startIndex, endIndex)
            : List.of();

        // Get program path for tracking
        String programPath = program.getDomainFile().getPathname();

        // Decompile each caller
        List<Map<String, Object>> decompilations = new ArrayList<>();
        DecompInterface decompiler = createConfiguredDecompilerForCallGraph(program);

        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }

        try {
            for (Function caller : pageCallers) {
                Map<String, Object> callerResult = new HashMap<>();
                callerResult.put("functionName", caller.getName());
                callerResult.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
                List<Address> sites = callSites.get(caller);
                if (sites != null) {
                    callerResult.put("callSites", sites.stream()
                        .map(AddressUtil::formatAddress)
                        .toList());
                } else {
                    callerResult.put("callSites", List.of());
                }

                DecompilationAttempt attempt = decompileFunctionSafelyForCallGraph(decompiler, caller);
                if (attempt.success()) {
                    String decompCode = attempt.results().getDecompiledFunction().getC();
                    callerResult.put("decompilation", decompCode);
                    callerResult.put("success", true);

                    // Find call line numbers if requested
                    if (includeCallContext) {
                        List<Integer> callLineNumbers = findCallLineNumbersForCallGraph(
                            attempt.results(), callSites.get(caller));
                        callerResult.put("callLineNumbers", callLineNumbers);
                    }

                    // Track that this function's decompilation has been read
                    String functionKey = programPath + ":" + AddressUtil.formatAddress(caller.getEntryPoint());
                    DecompilationReadTracker.markAsRead(functionKey);
                } else {
                    callerResult.put("success", false);
                    callerResult.put("error", attempt.errorMessage());
                }

                decompilations.add(callerResult);
            }
        } finally {
            decompiler.dispose();
        }

        // Build result
        Map<String, Object> result = new HashMap<>();
        result.put("programPath", programPath);
        result.put("targetFunction", targetFunction.getName());
        result.put("targetAddress", AddressUtil.formatAddress(targetFunction.getEntryPoint()));
        result.put("totalCallers", totalCallers);
        result.put("startIndex", startIndex);
        result.put("returnedCount", decompilations.size());
        result.put("nextStartIndex", startIndex + decompilations.size());
        result.put("hasMore", endIndex < totalCallers);
        result.put("callers", decompilations);

        return createJsonResult(result);
    }

    /**
     * Handle get-call-graph mode='common_callers' - find functions that call all specified functions
     */
    private McpSchema.CallToolResult handleFindCommonCallersMode(Program program, CallToolRequest request) {
        String functionAddresses = getOptionalString(request, "function_addresses", null);
        if (functionAddresses == null || functionAddresses.trim().isEmpty()) {
            return createErrorResult("function_addresses is required when mode='common_callers' (format: 'func1,func2,func3')");
        }

        // Parse comma-separated function addresses/names
        String[] addressStrings = functionAddresses.split(",");
        List<String> addressList = new ArrayList<>();
        for (String addrStr : addressStrings) {
            String trimmed = addrStr.trim();
            if (!trimmed.isEmpty()) {
                addressList.add(trimmed);
            }
        }

        if (addressList.isEmpty()) {
            return createErrorResult("At least one function address is required for mode='common_callers'");
        }

        List<Function> targetFunctions = new ArrayList<>();
        for (String addrStr : addressList) {
            Address addr = AddressUtil.resolveAddressOrSymbol(program, addrStr);
            if (addr == null) {
                return createErrorResult("Could not resolve address: " + addrStr);
            }
            Function func = resolveFunction(program, addr);
            if (func == null) {
                return createErrorResult("No function at address: " + addrStr);
            }
            targetFunctions.add(func);
        }

        return findCommonCallers(program, targetFunctions);
    }

    // ========================================================================
    // Decompiler Infrastructure for callers_decomp mode
    // ========================================================================

    private DecompInterface createConfiguredDecompilerForCallGraph(Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            logError("get-call-graph: Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    private DecompilationAttempt decompileFunctionSafelyForCallGraph(
            DecompInterface decompiler,
            Function function) {
        TaskMonitor timeoutMonitor = createTimeoutMonitor();
        DecompileResults results = decompiler.decompileFunction(function, 0, timeoutMonitor);

        if (timeoutMonitor.isCancelled()) {
            String msg = "Decompilation timed out after " + DEFAULT_TIMEOUT_SECONDS + " seconds";
            logError("get-call-graph: " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        if (!results.decompileCompleted()) {
            String msg = "Decompilation failed: " + results.getErrorMessage();
            logError("get-call-graph: " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        return DecompilationAttempt.success(results);
    }

    private List<Integer> findCallLineNumbersForCallGraph(DecompileResults results, List<Address> addresses) {
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
}
