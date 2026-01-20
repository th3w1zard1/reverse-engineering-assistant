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
package reva.tools.getfunction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.plugin.ConfigManager;
import reva.util.RevaInternalServiceRegistry;

import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.core.JsonProcessingException;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.listing.Variable;
import ghidra.util.exception.InvalidInputException;
import reva.tools.ProgramValidationException;

/**
 * Tool provider for get-function.
 * Provides function details in various formats: decompiled code, assembly, function information, or internal calls.
 */
public class GetFunctionToolProvider extends AbstractToolProvider {

    public GetFunctionToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerGetFunctionTool();
    }

    private void registerGetFunctionTool() {
        Map<String, Object> properties = new HashMap<>();
        Map<String, Object> programPathProperty = new HashMap<>();
        programPathProperty.put("oneOf", List.of(
            Map.of("type", "string", "description", "Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser."),
            Map.of("type", "array", "items", Map.of("type", "string"), "description", "Array of program paths for multi-program analysis")
        ));
        properties.put("programPath", programPathProperty);
        Map<String, Object> identifierProperty = new HashMap<>();
        identifierProperty.put("type", "string");
        identifierProperty.put("description", "Function name or address (e.g., 'main' or '0x401000'). Can be a single string or an array of strings for batch operations. When omitted, returns all functions.");
        Map<String, Object> identifierArraySchema = new HashMap<>();
        identifierArraySchema.put("type", "array");
        identifierArraySchema.put("items", Map.of("type", "string"));
        identifierArraySchema.put("description", "Array of function names or addresses for batch operations");
        identifierProperty.put("oneOf", List.of(
            Map.of("type", "string"),
            identifierArraySchema
        ));
        properties.put("identifier", identifierProperty);
        properties.put("view", Map.of(
            "type", "string",
            "description", "View mode: 'decompile', 'disassemble', 'info', 'calls'",
            "enum", List.of("decompile", "disassemble", "info", "calls"),
            "default", "decompile"
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Line number to start reading from when view='decompile' (1-based)",
            "default", 1
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Number of lines to return when view='decompile'",
            "default", 50
        ));
        properties.put("includeCallers", Map.of(
            "type", "boolean",
            "description", "Include list of functions that call this one when view='decompile'",
            "default", false
        ));
        properties.put("includeCallees", Map.of(
            "type", "boolean",
            "description", "Include list of functions this one calls when view='decompile'",
            "default", false
        ));
        properties.put("includeComments", Map.of(
            "type", "boolean",
            "description", "Whether to include comments in the decompilation when view='decompile'",
            "default", false
        ));
        properties.put("includeIncomingReferences", Map.of(
            "type", "boolean",
            "description", "Whether to include incoming cross references when view='decompile'",
            "default", true
        ));
        properties.put("includeReferenceContext", Map.of(
            "type", "boolean",
            "description", "Whether to include code context snippets from calling functions when view='decompile'",
            "default", true
        ));

        List<String> required = new ArrayList<>();

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-functions")
            .title("Get Functions")
            .description("Get function details in various formats: decompiled code, assembly, function information, or internal calls. Supports single function, batch operations when identifier is an array, or all functions when identifier is omitted.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                // Use getParameterAsList to support both camelCase and snake_case parameter names
                List<Object> identifierList = getParameterAsList(request.arguments(), "identifier");
                
                // When identifier is omitted, return all functions
                if (identifierList.isEmpty()) {
                    return handleAllFunctions(request);
                }

                // Handle programPath as array or string - supports both camelCase and snake_case
                List<Object> programPathList = getParameterAsList(request.arguments(), "programPath");
                if (programPathList.isEmpty()) {
                    programPathList = getParameterAsList(request.arguments(), "programPath");
                }
                Object programPathValue = programPathList.isEmpty() ? null : (programPathList.size() == 1 ? programPathList.get(0) : programPathList);
                Program program;
                if (programPathValue instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<String> programPaths = (List<String>) programPathValue;
                    if (programPaths.isEmpty()) {
                        return createErrorResult("programPath array cannot be empty");
                    }
                    program = reva.util.ProgramLookupUtil.getValidatedProgram(programPaths.get(0));
                } else {
                    program = getProgramFromArgs(request);
                }

                // Check if identifier is an array
                // Also check if the first element is itself a list (nested case)
                Object identifierValue = identifierList.get(0);
                if (identifierList.size() > 1 || (identifierValue instanceof List)) {
                    // Batch mode: use the list directly, or unwrap if nested
                    List<?> batchList = identifierList.size() > 1 ? identifierList : (List<?>) identifierValue;
                    return handleBatchGetFunction(program, request, batchList);
                }

                // Single function mode
                String identifier = identifierValue.toString();
                String view = getOptionalString(request, "view", "decompile");

                Function function = resolveFunction(program, identifier);
                if (function == null) {
                    return createErrorResult("Function not found: " + identifier);
                }

                // Intelligent bookmarking: check if function entry point should be bookmarked
                double bookmarkPercentile = reva.util.EnvConfigUtil.getDoubleDefault("auto_bookmark_percentile",
                    reva.util.IntelligentBookmarkUtil.getDefaultPercentile());
                reva.util.IntelligentBookmarkUtil.checkAndBookmarkIfFrequent(program, function.getEntryPoint(), bookmarkPercentile);

                return switch (view) {
                    case "decompile" -> handleDecompileView(program, function, request);
                    case "disassemble" -> handleDisassembleView(program, function);
                    case "info" -> handleInfoView(program, function);
                    case "calls" -> handleCallsView(program, function);
                    default -> createErrorResult("Invalid view mode: " + view);
                };
            } catch (IllegalArgumentException e) {
                // Try to return default response with error message
                Program program = tryGetProgramSafely(request.arguments());
                if (program != null) {
                    // Return empty result with error message
                    Map<String, Object> errorInfo = createIncorrectArgsErrorMap();
                    Map<String, Object> result = new HashMap<>();
                    result.put("error", errorInfo.get("error"));
                    result.put("programPath", program.getDomainFile().getPathname());
                    return createJsonResult(result);
                }
                // If we can't get a default response, return error with message
                return createErrorResult(e.getMessage() + " " + createIncorrectArgsErrorMap().get("error"));
            } catch (ProgramValidationException e) {
                logError("Error in get-function", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private Function resolveFunction(Program program, String identifier) {
        // Try as address or symbol first
        Address address = AddressUtil.resolveAddressOrSymbol(program, identifier);
        if (address != null) {
            Function function = AddressUtil.getContainingFunction(program, address);
            if (function != null) {
                return function;
            }
            // Try undefined function
            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS);
            Function undefinedFunction = UndefinedFunction.findFunction(program, address, monitor);
            if (undefinedFunction != null) {
                return undefinedFunction;
            }
        }

        // Try as function name
        FunctionManager functionManager = program.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext()) {
            Function f = functions.next();
            if (f.getName().equals(identifier) || f.getName().equalsIgnoreCase(identifier)) {
                return f;
            }
        }

        return null;
    }

    private McpSchema.CallToolResult handleDecompileView(Program program, Function function, CallToolRequest request) {
        int offset = getOptionalInt(request, "offset", 1);
        int limit = getOptionalInt(request, "limit", 50);
        boolean includeCallers = getOptionalBoolean(request, "includeCallers", false);
        boolean includeCallees = getOptionalBoolean(request, "includeCallees", false);
        boolean includeComments = getOptionalBoolean(request, "includeComments", false);
        boolean includeIncomingReferences = getOptionalBoolean(request, "includeIncomingReferences", true);
        boolean includeReferenceContext = getOptionalBoolean(request, "includeReferenceContext", true);

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("function", function.getName());
        resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        resultData.put("programName", program.getName());

        DecompInterface decompiler = createConfiguredDecompiler(program);
        if (decompiler == null) {
            resultData.put("decompilationError", "Failed to initialize decompiler");
            resultData.put("decompilation", "");
            return createJsonResult(resultData);
        }

        try {
            TaskMonitor monitor = createTimeoutMonitor();
            DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);

            if (monitor.isCancelled()) {
                return createErrorResult("Decompilation timed out after " + getTimeoutSeconds() + " seconds");
            }

            if (!decompileResults.decompileCompleted()) {
                return createErrorResult("Decompilation failed: " + decompileResults.getErrorMessage());
            }

            DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
            ClangTokenGroup markup = decompileResults.getCCodeMarkup();

            // Get synchronized decompilation with optional comments and incoming references
            Map<String, Object> syncedContent = getSynchronizedContent(program, markup, decompiledFunction.getC(),
                offset, limit, false, includeComments, includeIncomingReferences, includeReferenceContext, function);

            // Add content to results
            resultData.putAll(syncedContent);

            if (syncedContent.containsKey("decompilation")) {
                String decompCode = (String) syncedContent.get("decompilation");
                resultData.put("decompiledCode", decompCode);
                resultData.put("code", decompCode);
            }

            // Get additional details
            resultData.put("decompSignature", decompiledFunction.getSignature());

            // Add callers/callees if requested
            if (includeCallers) {
                List<Function> callers = new ArrayList<>();
                for (Function caller : function.getCallingFunctions(monitor)) {
                    callers.add(caller);
                }
                List<Map<String, Object>> callerInfo = new ArrayList<>();
                for (Function caller : callers) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("name", caller.getName());
                    info.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
                    callerInfo.add(info);
                }
                resultData.put("callers", callerInfo);
            }

            if (includeCallees) {
                List<Function> callees = new ArrayList<>();
                for (Function callee : function.getCalledFunctions(monitor)) {
                    callees.add(callee);
                }
                List<Map<String, Object>> calleeInfo = new ArrayList<>();
                for (Function callee : callees) {
                    Map<String, Object> info = new HashMap<>();
                    info.put("name", callee.getName());
                    info.put("address", AddressUtil.formatAddress(callee.getEntryPoint()));
                    calleeInfo.add(info);
                }
                resultData.put("callees", calleeInfo);
            }

            return createJsonResult(resultData);
        } catch (Exception e) {
            logError("Error during decompilation", e);
            return createErrorResult("Exception during decompilation: " + e.getMessage());
        } finally {
            decompiler.dispose();
        }
    }

    private McpSchema.CallToolResult handleDisassembleView(Program program, Function function) {
        List<Map<String, Object>> instructions = new ArrayList<>();
        Listing listing = program.getListing();

        for (Instruction instr : listing.getInstructions(function.getBody(), true)) {
            Map<String, Object> instrData = new HashMap<>();
            Address addr = instr.getMinAddress();
            instrData.put("address", AddressUtil.formatAddress(addr));
            instrData.put("instruction", instr.toString());

            CodeUnit codeUnit = listing.getCodeUnitAt(addr);
            if (codeUnit != null) {
                String comment = codeUnit.getComment(CommentType.EOL);
                if (comment == null || comment.isEmpty()) {
                    comment = codeUnit.getComment(CommentType.PRE);
                }
                if (comment != null && !comment.isEmpty()) {
                    instrData.put("comment", comment);
                }
            }

            instructions.add(instrData);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("function", function.getName());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("instructions", instructions);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleInfoView(Program program, Function function) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", function.getName());
        info.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        info.put("returnType", function.getReturnType().toString());
        info.put("callingConvention", function.getCallingConventionName());
        info.put("isExternal", function.isExternal());
        info.put("isThunk", function.isThunk());

        // Parameters
        List<Map<String, Object>> parameters = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            Parameter param = function.getParameter(i);
            Map<String, Object> paramInfo = new HashMap<>();
            paramInfo.put("name", param.getName());
            paramInfo.put("dataType", param.getDataType().toString());
            paramInfo.put("ordinal", i);
            parameters.add(paramInfo);
        }
        info.put("parameters", parameters);

        // Local variables
        List<Map<String, Object>> locals = new ArrayList<>();
        for (Variable local : function.getLocalVariables()) {
            Map<String, Object> localInfo = new HashMap<>();
            localInfo.put("name", local.getName());
            localInfo.put("dataType", local.getDataType().toString());
            locals.add(localInfo);
        }
        info.put("localVariables", locals);

        // Function body info
        var body = function.getBody();
        if (body != null && body.getMaxAddress() != null) {
            info.put("startAddress", AddressUtil.formatAddress(function.getEntryPoint()));
            info.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
            info.put("sizeInBytes", body.getNumAddresses());
        }

        return createJsonResult(info);
    }

    private McpSchema.CallToolResult handleCallsView(Program program, Function function) {
        List<Map<String, Object>> calls = new ArrayList<>();
        Listing listing = program.getListing();

        for (Instruction instr : listing.getInstructions(function.getBody(), true)) {
            Address[] flowDestinations = instr.getFlows();
            for (Address dest : flowDestinations) {
                Function calledFunc = program.getFunctionManager().getFunctionAt(dest);
                if (calledFunc != null) {
                    Map<String, Object> callInfo = new HashMap<>();
                    callInfo.put("address", AddressUtil.formatAddress(instr.getMinAddress()));
                    callInfo.put("calledFunction", calledFunc.getName());
                    callInfo.put("calledAddress", AddressUtil.formatAddress(dest));
                    calls.add(callInfo);
                }
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("function", function.getName());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("calls", calls);
        return createJsonResult(result);
    }

    private TaskMonitor createTimeoutMonitor() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = configManager != null ? configManager.getDecompilerTimeoutSeconds() : 60;
        return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
    }

    private DecompInterface createConfiguredDecompiler(Program program) {
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

    private int getTimeoutSeconds() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        return configManager != null ? configManager.getDecompilerTimeoutSeconds() : 60;
    }

    /** Map of Ghidra comment types to their string names for JSON output */
    private static final Map<CommentType, String> COMMENT_TYPE_NAMES = Map.of(
        CommentType.PRE, "pre",
        CommentType.EOL, "eol",
        CommentType.POST, "post",
        CommentType.PLATE, "plate",
        CommentType.REPEATABLE, "repeatable"
    );

    /**
     * Get synchronized decompilation content with optional comments and incoming references
     */
    private Map<String, Object> getSynchronizedContent(Program program, ClangTokenGroup markup,
            String fullDecompCode, int offset, Integer limit, boolean includeDisassembly,
            boolean includeComments, boolean includeIncomingReferences, boolean includeReferenceContext, Function function) {
        Map<String, Object> result = new HashMap<>();

        try {
            // Convert markup to lines
            String[] decompLines = fullDecompCode.split("\n");

            // Calculate range
            int totalLines = decompLines.length;
            int startIdx = Math.max(0, offset - 1); // Convert to 0-based
            int endIdx = limit != null ? Math.min(totalLines, startIdx + limit) : totalLines;

            result.put("totalLines", totalLines);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }

            // Include incoming references at the top level if requested
            if (includeIncomingReferences) {
                int maxIncomingRefs = 10;
                int totalRefCount = 0;
                var refIterator = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
                while (refIterator.hasNext()) {
                    refIterator.next();
                    totalRefCount++;
                }

                List<Map<String, Object>> incomingRefs = reva.util.DecompilationContextUtil
                    .getEnhancedIncomingReferences(program, function, includeReferenceContext, maxIncomingRefs);

                if (!incomingRefs.isEmpty()) {
                    result.put("incomingReferences", incomingRefs);
                    result.put("totalIncomingReferences", totalRefCount);

                    if (totalRefCount > maxIncomingRefs) {
                        result.put("incomingReferencesLimited", true);
                        result.put("incomingReferencesMessage", String.format(
                            "Showing first %d of %d references. Use 'find-cross-references' tool with target='%s' and mode='to' to see all references.",
                            maxIncomingRefs, totalRefCount, function.getName()
                        ));
                    }
                }
            }

            // Just return ranged decompilation (includeDisassembly not used in get-function view='decompile')
            StringBuilder rangedDecomp = new StringBuilder();
            for (int i = startIdx; i < endIdx; i++) {
                rangedDecomp.append(String.format("%4d\t%s\n", i + 1, decompLines[i]));
            }
            result.put("decompilation", rangedDecomp.toString());

            // Include all comments for the function if requested
            if (includeComments) {
                List<Map<String, Object>> functionComments = getAllCommentsInFunction(program, function);
                if (!functionComments.isEmpty()) {
                    result.put("comments", functionComments);
                }
            }

        } catch (Exception e) {
            logError("Error creating synchronized content", e);
            // Fallback to simple line range
            result.put("decompilation", applyLineRange(fullDecompCode, offset, limit));
            result.put("totalLines", fullDecompCode.split("\n").length);
            result.put("offset", offset);
            if (limit != null) {
                result.put("limit", limit);
            }
        }

        return result;
    }

    /**
     * Get all comments in a function
     */
    private List<Map<String, Object>> getAllCommentsInFunction(Program program, Function function) {
        List<Map<String, Object>> comments = new ArrayList<>();

        try {
            Listing listing = program.getListing();
            var body = function.getBody();

            CodeUnitIterator codeUnits = listing.getCodeUnits(body, true);
            while (codeUnits.hasNext()) {
                CodeUnit cu = codeUnits.next();
                Address addr = cu.getAddress();

                // Check all comment types
                for (Entry<CommentType, String> entry : COMMENT_TYPE_NAMES.entrySet()) {
                    addCommentIfExists(comments, cu, entry.getKey(), entry.getValue(), addr);
                }
            }
        } catch (Exception e) {
            logError("Error getting all comments in function", e);
        }

        return comments;
    }

    /**
     * Add a comment to the list if it exists
     */
    private void addCommentIfExists(List<Map<String, Object>> comments, CodeUnit cu,
            CommentType commentType, String typeString, Address address) {
        String comment = cu.getComment(commentType);
        if (comment != null && !comment.isEmpty()) {
            Map<String, Object> commentInfo = new HashMap<>();
            commentInfo.put("address", AddressUtil.formatAddress(address));
            commentInfo.put("type", typeString);
            commentInfo.put("comment", comment);
            comments.add(commentInfo);
        }
    }

    /**
     * Apply line range to text
     */
    private String applyLineRange(String text, int offset, Integer limit) {
        String[] lines = text.split("\n");
        int startIdx = Math.max(0, offset - 1); // Convert to 0-based
        int endIdx = limit != null ? Math.min(lines.length, startIdx + limit) : lines.length;

        StringBuilder result = new StringBuilder();
        for (int i = startIdx; i < endIdx; i++) {
            result.append(String.format("%4d\t%s\n", i + 1, lines[i]));
        }

        return result.toString();
    }

    /**
     * Handle batch get-functions operations when identifier is an array
     */
    private McpSchema.CallToolResult handleBatchGetFunction(Program program, CallToolRequest request, List<?> identifierList) {
        String view = getOptionalString(request, "view", "decompile");
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();

        for (int i = 0; i < identifierList.size(); i++) {
            try {
                String identifier = identifierList.get(i).toString();
                Function function = resolveFunction(program, identifier);
                if (function == null) {
                    errors.add(Map.of("index", i, "identifier", identifier, "error", "Function not found"));
                    continue;
                }

                Map<String, Object> functionResult = new HashMap<>();
                functionResult.put("index", i);
                functionResult.put("identifier", identifier);
                functionResult.put("name", function.getName());
                functionResult.put("address", AddressUtil.formatAddress(function.getEntryPoint()));

                switch (view) {
                    case "decompile" -> {
                        McpSchema.CallToolResult decompileResult = handleDecompileView(program, function, request);
                        if (decompileResult.isError()) {
                            String errorText = extractTextFromContent(decompileResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            // Extract structured data from JSON result
                            Map<String, Object> decompileData = extractJsonDataFromResult(decompileResult);
                            functionResult.putAll(decompileData);
                        }
                    }
                    case "disassemble" -> {
                        McpSchema.CallToolResult disassembleResult = handleDisassembleView(program, function);
                        if (disassembleResult.isError()) {
                            String errorText = extractTextFromContent(disassembleResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            Map<String, Object> disassembleData = extractJsonDataFromResult(disassembleResult);
                            functionResult.putAll(disassembleData);
                        }
                    }
                    case "info" -> {
                        McpSchema.CallToolResult infoResult = handleInfoView(program, function);
                        if (infoResult.isError()) {
                            String errorText = extractTextFromContent(infoResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            Map<String, Object> infoData = extractJsonDataFromResult(infoResult);
                            functionResult.putAll(infoData);
                        }
                    }
                    case "calls" -> {
                        McpSchema.CallToolResult callsResult = handleCallsView(program, function);
                        if (callsResult.isError()) {
                            String errorText = extractTextFromContent(callsResult.content().get(0));
                            errors.add(Map.of("index", i, "identifier", identifier, "error", errorText));
                        } else {
                            Map<String, Object> callsData = extractJsonDataFromResult(callsResult);
                            functionResult.putAll(callsData);
                        }
                    }
                    default -> {
                        errors.add(Map.of("index", i, "identifier", identifier, "error", "Invalid view: " + view));
                        continue;
                    }
                }

                results.add(functionResult);
            } catch (Exception e) {
                errors.add(Map.of("index", i, "identifier", identifierList.get(i).toString(), "error", e.getMessage()));
            }
        }

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("success", true);
        resultData.put("view", view);
        resultData.put("total", identifierList.size());
        resultData.put("succeeded", results.size());
        resultData.put("failed", errors.size());
        resultData.put("results", results);
        if (!errors.isEmpty()) {
            resultData.put("errors", errors);
        }

        return createJsonResult(resultData);
    }

    /**
     * Handle request when identifier is omitted - returns all functions
     */
    private McpSchema.CallToolResult handleAllFunctions(CallToolRequest request) {
        try {
            // Supports both camelCase and snake_case via getParameterValue
            List<Object> programPathList = getParameterAsList(request.arguments(), "programPath");
            Object programPathValue = programPathList.isEmpty() ? null : (programPathList.size() == 1 ? programPathList.get(0) : programPathList);
            List<Program> programs = new ArrayList<>();
            
            if (programPathValue instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> programPaths = (List<String>) programPathValue;
                for (String path : programPaths) {
                    try {
                        Program p = reva.util.ProgramLookupUtil.getValidatedProgram(path);
                        if (p != null && !p.isClosed()) {
                            programs.add(p);
                        }
                    } catch (ProgramValidationException e) {
                        // Skip invalid programs
                    }
                }
            } else {
                Program program = getProgramFromArgs(request);
                if (program != null) {
                    programs.add(program);
                }
            }
            
            if (programs.isEmpty()) {
                return createErrorResult("No valid programs found");
            }
            
            boolean filterDefaultNames = reva.util.EnvConfigUtil.getBooleanDefault("filter_default_names", true);
            List<Map<String, Object>> programResults = new ArrayList<>();
            int totalFunctions = 0;
            
            for (Program program : programs) {
                // Track initial function count for signature scanning
                FunctionManager funcManager = program.getFunctionManager();
                int initialFunctionCount = funcManager.getFunctionCount();
                
                // Run signature scanning to discover undefined functions
                Map<String, Object> signatureScanResults = runSignatureScanning(program);
                
                // Get final function count
                int finalFunctionCount = funcManager.getFunctionCount();
                int functionsDiscovered = finalFunctionCount - initialFunctionCount;
                
                // Collect all functions
                List<Map<String, Object>> functions = new ArrayList<>();
                FunctionIterator funcIter = funcManager.getFunctions(true);
                TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(300, TimeUnit.SECONDS);
                
                while (funcIter.hasNext() && !monitor.isCancelled()) {
                    Function function = funcIter.next();
                    
                    if (filterDefaultNames && reva.util.SymbolUtil.isDefaultSymbolName(function.getName())) {
                        continue;
                    }
                    
                    Map<String, Object> funcInfo = buildFunctionInfo(program, function, monitor);
                    functions.add(funcInfo);
                }
                
                // Build procedural/actions object
                Map<String, Object> actions = new HashMap<>();
                actions.put("signatureScanning", signatureScanResults);
                actions.put("functionsDiscovered", functionsDiscovered);
                actions.put("initialFunctionCount", initialFunctionCount);
                actions.put("finalFunctionCount", finalFunctionCount);
                
                Map<String, Object> programResult = new HashMap<>();
                programResult.put("programPath", program.getDomainFile().getPathname());
                programResult.put("totalFunctions", functions.size());
                programResult.put("functions", functions);
                programResult.put("actions", actions);
                programResults.add(programResult);
                totalFunctions += functions.size();
            }
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            if (programResults.size() == 1) {
                result.putAll(programResults.get(0));
            } else {
                result.put("programs", programResults);
                result.put("totalPrograms", programResults.size());
                result.put("totalFunctions", totalFunctions);
            }
            
            return createJsonResult(result);
        } catch (IllegalArgumentException | ProgramValidationException e) {
            logError("Error handling all functions", e);
            return createErrorResult("Failed to retrieve all functions: " + e.getMessage());
        }
    }
    
    /**
     * Build function info map (similar to handleInfoView but returns Map directly)
     */
    private Map<String, Object> buildFunctionInfo(Program program, Function function, TaskMonitor monitor) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", function.getName());
        info.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        info.put("returnType", function.getReturnType().toString());
        info.put("signature", function.getSignature().toString());
        info.put("callingConvention", function.getCallingConventionName());
        info.put("isExternal", function.isExternal());
        info.put("isThunk", function.isThunk());
        
        var body = function.getBody();
        if (body != null && body.getMaxAddress() != null) {
            info.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
            info.put("sizeInBytes", body.getNumAddresses());
        }
        
        // Parameters
        List<Map<String, Object>> parameters = new ArrayList<>();
        for (int i = 0; i < function.getParameterCount(); i++) {
            Parameter param = function.getParameter(i);
            Map<String, Object> paramInfo = new HashMap<>();
            paramInfo.put("name", param.getName());
            paramInfo.put("dataType", param.getDataType().toString());
            paramInfo.put("ordinal", i);
            parameters.add(paramInfo);
        }
        info.put("parameters", parameters);
        
        // Local variables
        List<Map<String, Object>> locals = new ArrayList<>();
        for (var local : function.getLocalVariables()) {
            Map<String, Object> localInfo = new HashMap<>();
            localInfo.put("name", local.getName());
            localInfo.put("dataType", local.getDataType().toString());
            locals.add(localInfo);
        }
        info.put("localVariables", locals);
        
        // Count callers and callees (with timeout)
        int callerCount = -1;
        int calleeCount = -1;
        if (monitor != null && !monitor.isCancelled()) {
            try {
                Set<Address> callerAddresses = new HashSet<>();
                var refManager = program.getReferenceManager();
                var refsTo = refManager.getReferencesTo(function.getEntryPoint());
                int refCount = 0;
                while (refsTo.hasNext() && !monitor.isCancelled()) {
                    if (++refCount % 1000 == 0 && monitor.isCancelled()) break;
                    var ref = refsTo.next();
                    if (ref.getReferenceType().isCall()) {
                        Function caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            callerAddresses.add(caller.getEntryPoint());
                        }
                    }
                }
                callerCount = monitor.isCancelled() ? -1 : callerAddresses.size();
                
                if (!monitor.isCancelled()) {
                    Set<Address> calleeAddresses = new HashSet<>();
                    for (Instruction instr : program.getListing().getInstructions(body, true)) {
                        if (monitor.isCancelled()) break;
                        Reference[] refsFrom = instr.getReferencesFrom();
                        for (Reference ref : refsFrom) {
                            if (ref.getReferenceType().isCall()) {
                                Function callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                                if (callee == null) {
                                    callee = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
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
                // Leave as -1 if counting fails
            }
        }
        info.put("callerCount", callerCount);
        info.put("calleeCount", calleeCount);
        
        return info;
    }
    
    /**
     * Run signature scanning to discover undefined functions
     */
    private Map<String, Object> runSignatureScanning(Program program) {
        Map<String, Object> results = new HashMap<>();
        int functionsCreated = 0;
        List<Map<String, Object>> discoveredFunctions = new ArrayList<>();
        
        try {
            FunctionManager funcManager = program.getFunctionManager();
            Listing listing = program.getListing();
            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(60, TimeUnit.SECONDS);
            
            // Find undefined functions (addresses that are called but don't have functions)
            Set<Address> calledAddresses = new HashSet<>();
            FunctionIterator funcIter = funcManager.getFunctions(true);
            
            // Collect all call targets
            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                AddressSetView body = func.getBody();
                if (body == null) continue;
                
                for (Instruction instr : listing.getInstructions(body, true)) {
                    if (monitor.isCancelled()) break;
                    Reference[] refs = instr.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) {
                            Address targetAddr = ref.getToAddress();
                            Function targetFunc = funcManager.getFunctionAt(targetAddr);
                            if (targetFunc == null) {
                                // Check if it's valid code
                                CodeUnit cu = listing.getCodeUnitAt(targetAddr);
                                if (cu != null && cu instanceof Instruction) {
                                    calledAddresses.add(targetAddr);
                                }
                            }
                        }
                    }
                }
            }
            
            // Try to create functions at undefined call targets
            int txId = program.startTransaction("Signature Scanning - Create Functions");
            try {
                for (Address addr : calledAddresses) {
                    if (monitor.isCancelled()) break;
                    if (funcManager.getFunctionAt(addr) == null) {
                        try {
                            Function newFunc = funcManager.createFunction(null, addr, null, ghidra.program.model.symbol.SourceType.ANALYSIS);
                            if (newFunc != null) {
                                functionsCreated++;
                                discoveredFunctions.add(Map.of(
                                    "address", AddressUtil.formatAddress(addr),
                                    "name", newFunc.getName()
                                ));
                            }
                        } catch (OverlappingFunctionException | InvalidInputException e) {
                            // Skip if function creation fails
                        }
                    }
                }
                program.endTransaction(txId, true);
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
            
            results.put("success", true);
            results.put("functionsCreated", functionsCreated);
            results.put("discoveredFunctions", discoveredFunctions);
        } catch (Exception e) {
            logError("Error running signature scanning", e);
            results.put("success", false);
            results.put("error", e.getMessage());
        }
        
        return results;
    }

    /**
     * Extract JSON data from a CallToolResult, returning the parsed map
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractJsonDataFromResult(McpSchema.CallToolResult result) {
        try {
            String jsonText = extractTextFromContent(result.content().get(0));
            return JSON.readValue(jsonText, Map.class);
        } catch (JsonProcessingException e) {
            // Fallback: return empty map if parsing fails
            logError("Error extracting JSON data from result", e);
            return new HashMap<>();
        }
    }

}
