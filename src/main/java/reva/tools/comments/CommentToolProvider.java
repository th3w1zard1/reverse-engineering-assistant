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
package reva.tools.comments;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.regex.PatternSyntaxException;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DecompilationReadTracker;
import reva.util.RevaInternalServiceRegistry;
import reva.util.SchemaUtil;
import reva.util.SmartSuggestionsUtil;

/**
 * Tool provider for comment-related operations.
 * Provides tools to set, get, remove, and search comments in programs.
 */
public class CommentToolProvider extends AbstractToolProvider {

    private static final Map<String, CommentType> COMMENT_TYPES = Map.of(
        "pre", CommentType.PRE,
        "eol", CommentType.EOL,
        "post", CommentType.POST,
        "plate", CommentType.PLATE,
        "repeatable", CommentType.REPEATABLE
    );

    /**
     * Record for decompilation attempts with error handling
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
     * Constructor
     * @param server The MCP server
     */
    public CommentToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageCommentsTool();
    }

    private void registerManageCommentsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser."));
        properties.put("action", Map.of(
            "type", "string",
            "description", "Action to perform: 'set', 'get', 'remove', 'search', or 'search_decomp'",
            "enum", List.of("set", "get", "remove", "search", "search_decomp")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address where to set/get/remove the comment (required for set/remove when not using function/line_number)"));
        properties.put("address_or_symbol", SchemaUtil.stringProperty("Address or symbol name (alternative parameter)"));
        properties.put("function", SchemaUtil.stringProperty("Function name or address when setting decompilation line comment or searching decompilation"));
        properties.put("function_name_or_address", SchemaUtil.stringProperty("Function name or address (alternative parameter name)"));
        properties.put("line_number", SchemaUtil.integerProperty("Line number in the decompiled function when action='set' with decompilation (1-based)"));
        properties.put("comment", SchemaUtil.stringProperty("The comment text to set (required for set when not using batch mode)"));
        properties.put("comment_type", SchemaUtil.stringPropertyWithDefault("Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable')", "eol"));
        // Batch comments array - array of objects
        Map<String, Object> commentItemSchema = new HashMap<>();
        commentItemSchema.put("type", "object");
        Map<String, Object> commentItemProperties = new HashMap<>();
        commentItemProperties.put("address", SchemaUtil.stringProperty("Address or symbol name where to set the comment"));
        commentItemProperties.put("comment", SchemaUtil.stringProperty("The comment text to set"));
        commentItemProperties.put("comment_type", SchemaUtil.stringPropertyWithDefault("Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable')", "eol"));
        commentItemSchema.put("properties", commentItemProperties);
        commentItemSchema.put("required", List.of("address", "comment"));

        Map<String, Object> commentsArraySchema = new HashMap<>();
        commentsArraySchema.put("type", "array");
        commentsArraySchema.put("description", "Array of comment objects for batch setting. Each object should have 'address' (required), 'comment' (required), and optional 'comment_type' (defaults to 'eol'). When provided, sets multiple comments in a single transaction.");
        commentsArraySchema.put("items", commentItemSchema);
        properties.put("comments", commentsArraySchema);
        properties.put("start", SchemaUtil.stringProperty("Start address of the range when action='get'"));
        properties.put("end", SchemaUtil.stringProperty("End address of the range when action='get'"));
        properties.put("comment_types", SchemaUtil.stringProperty("Types of comments to retrieve/search (comma-separated: pre,eol,post,plate,repeatable)"));
        properties.put("search_text", SchemaUtil.stringProperty("Text to search for in comments when action='search'"));
        properties.put("pattern", SchemaUtil.stringProperty("Regular expression pattern to search for when action='search_decomp'"));
        properties.put("case_sensitive", SchemaUtil.booleanPropertyWithDefault("Whether search is case sensitive", false));
        properties.put("max_results", SchemaUtil.integerPropertyWithDefault("Maximum number of results to return", 100));
        properties.put("override_max_functions_limit", SchemaUtil.booleanPropertyWithDefault("Whether to override the maximum function limit for decompiler searches", false));

        List<String> required = List.of("action");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-comments")
            .title("Manage Comments")
            .description("Set, get, remove, or search comments in decompiled code, disassembly, or at addresses. Also search patterns across all decompilations.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String action = getString(request, "action");

                switch (action) {
                    case "set":
                        return handleSetComment(program, request);
                    case "get":
                        return handleGetComments(program, request);
                    case "remove":
                        return handleRemoveComment(program, request);
                    case "search":
                        return handleSearchComments(program, request);
                    case "search_decomp":
                        return handleSearchDecompilation(program, request, exchange);
                    default:
                        return createErrorResult("Invalid action: " + action + ". Valid actions are: set, get, remove, search, search_decomp");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in manage-comments", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    // ========================================================================
    // Helper Methods for Decompilation Comments
    // ========================================================================

    /**
     * Create a configured decompiler instance
     */
    private DecompInterface createConfiguredDecompilerForComments(Program program, String toolName) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            decompiler.dispose();
            return null;
        }

        return decompiler;
    }

    /**
     * Safely decompile a function with timeout handling
     */
    private DecompilationAttempt decompileFunctionSafelyForComments(
            DecompInterface decompiler,
            Function function,
            String toolName) {
        ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(
            config.getDecompilerTimeoutSeconds(),
            TimeUnit.SECONDS);

        try {
            DecompileResults results = decompiler.decompileFunction(function, 0, monitor);
            if (monitor.isCancelled()) {
                String msg = "Decompilation timed out for function " + function.getName() +
                    " after " + config.getDecompilerTimeoutSeconds() + " seconds";
                return DecompilationAttempt.failure(msg);
            }

            if (!results.decompileCompleted()) {
                String msg = "Decompilation failed for function " + function.getName() +
                    ": " + results.getErrorMessage();
                return DecompilationAttempt.failure(msg);
            }

            return DecompilationAttempt.success(results);
        } catch (Exception e) {
            String msg = "Exception during decompilation of " + function.getName() + ": " + e.getMessage();
            logError(toolName + ": " + msg, e);
            return DecompilationAttempt.failure(msg);
        }
    }

    /**
     * Find the address corresponding to a decompilation line number
     */
    private Address findAddressForLine(Program program, List<ClangLine> clangLines, int lineNumber) {
        for (ClangLine clangLine : clangLines) {
            if (clangLine.getLineNumber() == lineNumber) {
                List<ClangToken> tokens = clangLine.getAllTokens();

                // Find the first address on this line
                for (ClangToken token : tokens) {
                    Address tokenAddr = token.getMinAddress();
                    if (tokenAddr != null) {
                        return tokenAddr;
                    }
                }

                // If no direct address, find closest
                if (!tokens.isEmpty()) {
                    return DecompilerUtils.getClosestAddress(program, tokens.get(0));
                }
                break;
            }
        }
        return null;
    }

    /**
     * Check if a function's decompilation has been read (for line comment validation)
     * Uses the shared DecompilationReadTracker so it can see reads from DecompilerToolProvider
     */
    private boolean hasReadDecompilation(String functionKey) {
        return DecompilationReadTracker.hasReadDecompilation(functionKey);
    }

    private McpSchema.CallToolResult handleSetComment(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        // Check for batch mode (comments array)
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> commentsArray = getOptionalCommentsArray(request);

        if (commentsArray != null && !commentsArray.isEmpty()) {
            return handleBatchSetComments(program, request, commentsArray);
        }

        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }

        // Check if setting decompilation line comment (function + line_number instead of address)
        String functionStr = getOptionalString(request, "function", null);
        if (functionStr == null) {
            functionStr = getOptionalString(request, "function_name_or_address", null);
        }
        Integer lineNumber = getOptionalInteger(request.arguments(), "line_number", null);
        if (lineNumber == null) {
            lineNumber = getOptionalInteger(request.arguments(), "lineNumber", null);
        }

        // If we have function and line_number but no address, this is a decompilation line comment
        if (addressStr == null && functionStr != null && lineNumber != null) {
            return handleSetDecompilationLineComment(program, request, functionStr, lineNumber);
        }

        // Regular address-based comment
        if (addressStr == null) {
            return createErrorResult("address is required for action='set' (or use 'comments' array for batch mode, or use function and line_number for decompilation line comments)");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        // Intelligent bookmarking: check if address should be bookmarked
        double bookmarkPercentile = reva.util.EnvConfigUtil.getDoubleDefault("auto_bookmark_percentile",
            reva.util.IntelligentBookmarkUtil.getDefaultPercentile());
        reva.util.IntelligentBookmarkUtil.checkAndBookmarkIfFrequent(program, address, bookmarkPercentile);

        String commentTypeStr = getOptionalString(request, "comment_type", null);
        if (commentTypeStr == null) {
            commentTypeStr = getOptionalString(request, "commentType", null);
        }

        // Auto-label comment type if not provided (controlled by environment variable)
        boolean autoLabel = reva.util.EnvConfigUtil.getBooleanDefault("auto_label", true);
        if (autoLabel && commentTypeStr == null) {
            Map<String, Object> suggestion = SmartSuggestionsUtil.suggestCommentType(program, address);
            commentTypeStr = (String) suggestion.get("comment_type");
        }

        if (commentTypeStr == null) {
            commentTypeStr = "eol"; // Default fallback
        }

        String comment = getOptionalString(request, "comment", null);

        // Auto-label comment text if not provided (controlled by environment variable)
        if (autoLabel && (comment == null || comment.trim().isEmpty())) {
            Map<String, Object> commentSuggestion = SmartSuggestionsUtil.suggestCommentText(program, address);
            comment = (String) commentSuggestion.get("text");
        }

        if (comment == null || comment.trim().isEmpty()) {
            return createErrorResult("comment is required for action='set'");
        }

        CommentType commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
        if (commentType == null) {
            return createErrorResult("Invalid comment type: " + commentTypeStr +
                ". Must be one of: pre, eol, post, plate, repeatable");
        }

        try {
            int transactionId = program.startTransaction("Set Comment");
            try {
                Listing listing = program.getListing();
                listing.setComment(address, commentType, comment);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("address", AddressUtil.formatAddress(address));
                result.put("commentType", commentTypeStr);
                result.put("comment", comment);

                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Set comment");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error setting comment", e);
            return createErrorResult("Failed to set comment: " + e.getMessage());
        }
    }

    /**
     * Get optional comments array from request for batch operations
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getOptionalCommentsArray(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Object value = request.arguments().get("comments");
        if (value == null) {
            return null;
        }
        if (value instanceof List) {
            return (List<Map<String, Object>>) value;
        }
        throw new IllegalArgumentException("Parameter 'comments' must be an array");
    }

    /**
     * Handle batch setting of multiple comments in a single transaction
     */
    private McpSchema.CallToolResult handleBatchSetComments(Program program,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            List<Map<String, Object>> commentsArray) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        Listing listing = program.getListing();

        try {
            int transactionId = program.startTransaction("Batch Set Comments");
            try {
                for (int i = 0; i < commentsArray.size(); i++) {
                    Map<String, Object> commentObj = commentsArray.get(i);

                    // Extract address
                    Object addressObj = commentObj.get("address");
                    if (addressObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'address' field in comment object"));
                        continue;
                    }
                    String addressStr = addressObj.toString();

                    // Extract comment text
                    Object commentObjValue = commentObj.get("comment");
                    if (commentObjValue == null) {
                        errors.add(createErrorInfo(i, "Missing 'comment' field in comment object"));
                        continue;
                    }
                    String comment = commentObjValue.toString();

                    // Extract comment type (optional, defaults to "eol")
                    String commentTypeStr = "eol";
                    Object commentTypeObj = commentObj.get("comment_type");
                    if (commentTypeObj != null) {
                        commentTypeStr = commentTypeObj.toString();
                    } else {
                        // Also check camelCase variant
                        commentTypeObj = commentObj.get("commentType");
                        if (commentTypeObj != null) {
                            commentTypeStr = commentTypeObj.toString();
                        }
                    }

                    // Resolve address
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                    if (address == null) {
                        errors.add(createErrorInfo(i, "Could not resolve address or symbol: " + addressStr));
                        continue;
                    }

                    // Validate comment type
                    CommentType commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
                    if (commentType == null) {
                        errors.add(createErrorInfo(i, "Invalid comment type: " + commentTypeStr +
                            ". Must be one of: pre, eol, post, plate, repeatable"));
                        continue;
                    }

                    // Set the comment
                    listing.setComment(address, commentType, comment);

                    // Record success
                    Map<String, Object> result = new HashMap<>();
                    result.put("index", i);
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("commentType", commentTypeStr);
                    result.put("comment", comment);
                    results.add(result);
                }

                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Batch set comments");

                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("total", commentsArray.size());
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
            logError("Error in batch set comments", e);
            return createErrorResult("Failed to batch set comments: " + e.getMessage());
        }
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

    private McpSchema.CallToolResult handleSetDecompilationLineComment(Program program,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            String functionStr, int lineNumber) {
        String commentTypeStr = getOptionalString(request, "comment_type", null);
        if (commentTypeStr == null) {
            commentTypeStr = getOptionalString(request, "commentType", "eol");
        }
        String comment = getString(request, "comment");

        // Validate comment type (only 'pre' and 'eol' are valid for decompilation comments)
        CommentType commentType;
        if ("pre".equals(commentTypeStr.toLowerCase())) {
            commentType = CommentType.PRE;
        } else if ("eol".equals(commentTypeStr.toLowerCase())) {
            commentType = CommentType.EOL;
        } else {
            return createErrorResult("Invalid comment type: " + commentTypeStr +
                ". Must be 'pre' or 'eol' for decompilation comments.");
        }

        // Get function
        Function function;
        try {
            Address funcAddr = AddressUtil.resolveAddressOrSymbol(program, functionStr);
            if (funcAddr == null) {
                return createErrorResult("Could not resolve function address or symbol: " + functionStr);
            }
            function = program.getFunctionManager().getFunctionContaining(funcAddr);
            if (function == null) {
                if (AddressUtil.isUndefinedFunctionAddress(program, functionStr)) {
                    return createErrorResult("Cannot set comment at " + functionStr +
                        ": this address has code but no defined function. " +
                        "Comments require a defined function. " +
                        "Use create-function to define it first, then retry.");
                }
                return createErrorResult("Function not found at: " + functionStr);
            }
        } catch (Exception e) {
            return createErrorResult("Error resolving function: " + e.getMessage());
        }

        // Validate that the decompilation has been read for this function first
        String programPath = getString(request, "programPath");
        String functionKey = programPath + ":" + AddressUtil.formatAddress(function.getEntryPoint());

        // If decompilation hasn't been read yet, we'll decompile it in this method anyway,
        // so populate the tracker now to allow the operation to proceed
        // (the user will see the decompilation when we decompile it below)
        if (!hasReadDecompilation(functionKey)) {
            // Populate tracker now since we're about to decompile anyway
            DecompilationReadTracker.markAsRead(functionKey);
        }

        // Initialize decompiler
        final String toolName = "manage-comments-set";
        DecompInterface decompiler = createConfiguredDecompilerForComments(program, toolName);
        if (decompiler == null) {
            return createErrorResult("Failed to initialize decompiler");
        }

        try {
            // Decompile the function
            DecompilationAttempt attempt = decompileFunctionSafelyForComments(decompiler, function, toolName);
            if (!attempt.success()) {
                return createErrorResult(attempt.errorMessage());
            }

            // Track that this function's decompilation has been read (populate after successful decompilation)
            DecompilationReadTracker.markAsRead(functionKey);

            // Get the decompiled code and markup
            ClangTokenGroup markup = attempt.results().getCCodeMarkup();
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);

            // Find the address for the specified line number
            Address targetAddress = findAddressForLine(program, clangLines, lineNumber);
            if (targetAddress == null) {
                return createErrorResult("Could not find an address for line " + lineNumber +
                    " in decompiled function. The line may not correspond to any actual code.");
            }

            // Set the comment
            int transactionId = program.startTransaction("Set Decompilation Comment");
            try {
                Listing listing = program.getListing();
                listing.setComment(targetAddress, commentType, comment);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("functionName", function.getName());
                result.put("lineNumber", lineNumber);
                result.put("address", AddressUtil.formatAddress(targetAddress));
                result.put("commentType", commentTypeStr);
                result.put("comment", comment);

                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Set decompilation comment");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError(toolName + ": Error setting decompilation line comment for " + function.getName(), e);
            return createErrorResult("Failed to set decompilation line comment: " + e.getMessage());
        } finally {
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult handleGetComments(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }
        String startStr = getOptionalString(request, "start", null);
        String endStr = getOptionalString(request, "end", null);
        String commentTypesStr = getOptionalString(request, "comment_types", null);
        if (commentTypesStr == null) {
            commentTypesStr = getOptionalString(request, "commentTypes", null);
        }

        AddressSetView addresses;
        if (addressStr != null) {
            Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
            if (address == null) {
                return createErrorResult("Could not resolve address or symbol: " + addressStr);
            }
            addresses = new AddressSet(address, address);
        } else if (startStr != null && endStr != null) {
            Address start = AddressUtil.resolveAddressOrSymbol(program, startStr);
            Address end = AddressUtil.resolveAddressOrSymbol(program, endStr);
            if (start == null || end == null) {
                return createErrorResult("Invalid address range");
            }
            addresses = new AddressSet(start, end);
        } else {
            return createErrorResult("Either 'address' or 'start'/'end' range must be provided");
        }

        List<CommentType> types = new ArrayList<>();
        if (commentTypesStr != null && !commentTypesStr.isEmpty()) {
            String[] typeStrs = commentTypesStr.split(",");
            for (String typeStr : typeStrs) {
                CommentType type = COMMENT_TYPES.get(typeStr.trim().toLowerCase());
                if (type == null) {
                    return createErrorResult("Invalid comment type: " + typeStr);
                }
                types.add(type);
            }
        } else {
            List<String> commentTypesList = getOptionalStringList(request.arguments(), "commentTypes", null);
            if (commentTypesList != null && !commentTypesList.isEmpty()) {
                for (String typeStr : commentTypesList) {
                    CommentType type = COMMENT_TYPES.get(typeStr.toLowerCase());
                    if (type == null) {
                        return createErrorResult("Invalid comment type: " + typeStr);
                    }
                    types.add(type);
                }
            } else {
                types.addAll(COMMENT_TYPES.values());
            }
        }

        List<Map<String, Object>> comments = new ArrayList<>();
        Listing listing = program.getListing();

        CodeUnitIterator codeUnits = listing.getCodeUnits(addresses, true);
        while (codeUnits.hasNext()) {
            CodeUnit codeUnit = codeUnits.next();
            Address addr = codeUnit.getAddress();

            for (CommentType type : types) {
                String comment = codeUnit.getComment(type);
                if (comment != null && !comment.isEmpty()) {
                    Map<String, Object> commentInfo = new HashMap<>();
                    commentInfo.put("address", AddressUtil.formatAddress(addr));
                    commentInfo.put("commentType", getCommentTypeName(type));
                    commentInfo.put("comment", comment);
                    comments.add(commentInfo);
                }
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("comments", comments);
        result.put("count", comments.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleRemoveComment(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }
        if (addressStr == null) {
            return createErrorResult("address is required for action='remove'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        // Intelligent bookmarking: check if address should be bookmarked
        double bookmarkPercentile = reva.util.EnvConfigUtil.getDoubleDefault("auto_bookmark_percentile",
            reva.util.IntelligentBookmarkUtil.getDefaultPercentile());
        reva.util.IntelligentBookmarkUtil.checkAndBookmarkIfFrequent(program, address, bookmarkPercentile);

        String commentTypeStr = getOptionalString(request, "comment_type", null);
        if (commentTypeStr == null) {
            commentTypeStr = getOptionalString(request, "commentType", null);
        }
        if (commentTypeStr == null) {
            return createErrorResult("comment_type is required for action='remove'");
        }

        CommentType commentType = COMMENT_TYPES.get(commentTypeStr.toLowerCase());
        if (commentType == null) {
            return createErrorResult("Invalid comment type: " + commentTypeStr +
                ". Must be one of: pre, eol, post, plate, repeatable");
        }

        try {
            int transactionId = program.startTransaction("Remove Comment");
            try {
                Listing listing = program.getListing();
                listing.setComment(address, commentType, null);

                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("address", AddressUtil.formatAddress(address));
                result.put("commentType", commentTypeStr);

                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Remove comment");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error removing comment", e);
            return createErrorResult("Failed to remove comment: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleSearchComments(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String searchText = getOptionalString(request, "search_text", null);
        if (searchText == null) {
            searchText = getOptionalString(request, "searchText", null);
        }
        if (searchText == null) {
            return createErrorResult("search_text is required for action='search'");
        }

        boolean caseSensitive = getOptionalBoolean(request, "case_sensitive",
            getOptionalBoolean(request, "caseSensitive", false));

        String commentTypesStr = getOptionalString(request, "comment_types", null);
        List<String> commentTypesList = getOptionalStringList(request.arguments(), "commentTypes", null);

        int maxResults = getOptionalInt(request, "max_results",
            getOptionalInt(request, "maxResults", 100));

        List<CommentType> types = new ArrayList<>();
        if (commentTypesStr != null && !commentTypesStr.isEmpty()) {
            String[] typeStrs = commentTypesStr.split(",");
            for (String typeStr : typeStrs) {
                CommentType type = COMMENT_TYPES.get(typeStr.trim().toLowerCase());
                if (type == null) {
                    return createErrorResult("Invalid comment type: " + typeStr);
                }
                types.add(type);
            }
        } else if (commentTypesList != null && !commentTypesList.isEmpty()) {
            for (String typeStr : commentTypesList) {
                CommentType type = COMMENT_TYPES.get(typeStr.toLowerCase());
                if (type == null) {
                    return createErrorResult("Invalid comment type: " + typeStr);
                }
                types.add(type);
            }
        } else {
            types.addAll(COMMENT_TYPES.values());
        }

        String searchLower = caseSensitive ? searchText : searchText.toLowerCase();
        List<Map<String, Object>> results = new ArrayList<>();
        Listing listing = program.getListing();

        for (CommentType type : types) {
            if (results.size() >= maxResults) break;

            AddressIterator commentAddrs = listing.getCommentAddressIterator(
                type, program.getMemory(), true);

            while (commentAddrs.hasNext() && results.size() < maxResults) {
                Address addr = commentAddrs.next();
                String comment = listing.getComment(type, addr);

                if (comment != null) {
                    String commentLower = caseSensitive ? comment : comment.toLowerCase();
                    if (commentLower.contains(searchLower)) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("address", AddressUtil.formatAddress(addr));
                        result.put("commentType", getCommentTypeName(type));
                        result.put("comment", comment);

                        CodeUnit cu = listing.getCodeUnitAt(addr);
                        if (cu != null) {
                            result.put("codeUnit", cu.toString());
                        }

                        results.add(result);
                    }
                }
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("searchText", searchText);
        result.put("caseSensitive", caseSensitive);
        result.put("results", results);
        result.put("count", results.size());
        result.put("maxResults", maxResults);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSearchDecompilation(Program program,
            io.modelcontextprotocol.spec.McpSchema.CallToolRequest request,
            io.modelcontextprotocol.server.McpSyncServerExchange exchange) {
        String pattern = getOptionalString(request, "pattern", null);
        if (pattern == null) {
            return createErrorResult("pattern is required for action='search_decomp'");
        }

        boolean caseSensitive = getOptionalBoolean(request, "case_sensitive",
            getOptionalBoolean(request, "caseSensitive", false));
        int maxResults = getOptionalInt(request, "max_results",
            getOptionalInt(request, "maxResults", 50));
        boolean overrideMaxFunctionsLimit = getOptionalBoolean(request, "override_max_functions_limit",
            getOptionalBoolean(request, "overrideMaxFunctionsLimit", false));

        if (pattern.trim().isEmpty()) {
            return createErrorResult("Search pattern cannot be empty");
        }

        ConfigManager config = RevaInternalServiceRegistry.getService(ConfigManager.class);
        int maxFunctions = config.getMaxDecompilerSearchFunctions();
        FunctionManager functionManager = program.getFunctionManager();
        if (functionManager.getFunctionCount() > maxFunctions && !overrideMaxFunctionsLimit) {
            return createErrorResult("Program has " + functionManager.getFunctionCount() +
                " functions, which exceeds the maximum limit of " + maxFunctions +
                ". Use 'override_max_functions_limit' to bypass this check.");
        }

        try {
            int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
            Pattern regex = Pattern.compile(pattern, flags);

            DecompInterface decompiler = createConfiguredDecompilerForComments(program, "manage-comments-search_decomp");
            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            List<Map<String, Object>> searchResults = new ArrayList<>();
            try {
                FunctionIterator functions = functionManager.getFunctions(true);
                while (functions.hasNext() && searchResults.size() < maxResults) {
                    Function function = functions.next();

                    if (function.isExternal()) {
                        continue;
                    }

                    try {
                        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(
                            config.getDecompilerTimeoutSeconds(),
                            TimeUnit.SECONDS);
                        DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);

                        if (monitor.isCancelled()) {
                            continue;
                        }

                        if (decompileResults.decompileCompleted()) {
                            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
                            String decompCode = decompiledFunction.getC();
                            String[] lines = decompCode.split("\n");

                            for (int i = 0; i < lines.length && searchResults.size() < maxResults; i++) {
                                String line = lines[i];
                                Matcher matcher = regex.matcher(line);

                                if (matcher.find()) {
                                    Map<String, Object> result = new HashMap<>();
                                    result.put("functionName", function.getName());
                                    result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
                                    result.put("lineNumber", i + 1);
                                    result.put("lineContent", line.trim());
                                    result.put("matchStart", matcher.start());
                                    result.put("matchEnd", matcher.end());
                                    result.put("matchedText", matcher.group());
                                    searchResults.add(result);
                                }
                            }
                        }
                    } catch (Exception e) {
                        continue;
                    }
                }
            } finally {
                decompiler.dispose();
            }

            Map<String, Object> result = new HashMap<>();
            result.put("pattern", pattern);
            result.put("caseSensitive", caseSensitive);
            result.put("results", searchResults);
            result.put("resultsCount", searchResults.size());
            result.put("maxResults", maxResults);
            return createJsonResult(result);
        } catch (PatternSyntaxException e) {
            return createErrorResult("Invalid regex pattern: " + e.getMessage());
        } catch (Exception e) {
            logError("Error during decompilation search", e);
            return createErrorResult("Search failed: " + e.getMessage());
        }
    }

    /**
     * Get the string name for a comment type constant
     * @param commentType The comment type enum
     * @return The string name
     */
    private String getCommentTypeName(CommentType commentType) {
        for (Map.Entry<String, CommentType> entry : COMMENT_TYPES.entrySet()) {
            if (entry.getValue() == commentType) {
                return entry.getKey();
            }
        }
        return "unknown";
    }
}
