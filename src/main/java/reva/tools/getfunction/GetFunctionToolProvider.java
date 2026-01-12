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

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
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

/**
 * Tool provider for get_function.
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
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program"
        ));
        properties.put("identifier", Map.of(
            "type", "string",
            "description", "Function name or address (e.g., 'main' or '0x401000')"
        ));
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
        properties.put("include_callers", Map.of(
            "type", "boolean",
            "description", "Include list of functions that call this one when view='decompile'",
            "default", false
        ));
        properties.put("include_callees", Map.of(
            "type", "boolean",
            "description", "Include list of functions this one calls when view='decompile'",
            "default", false
        ));
        properties.put("include_comments", Map.of(
            "type", "boolean",
            "description", "Whether to include comments in the decompilation when view='decompile'",
            "default", false
        ));
        properties.put("include_incoming_references", Map.of(
            "type", "boolean",
            "description", "Whether to include incoming cross references when view='decompile'",
            "default", true
        ));
        properties.put("include_reference_context", Map.of(
            "type", "boolean",
            "description", "Whether to include code context snippets from calling functions when view='decompile'",
            "default", true
        ));

        List<String> required = List.of("programPath", "identifier");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get_function")
            .title("Get Function")
            .description("Get function details in various formats: decompiled code, assembly, function information, or internal calls")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String identifier = getString(request, "identifier");
                String view = getOptionalString(request, "view", "decompile");

                Function function = resolveFunction(program, identifier);
                if (function == null) {
                    return createErrorResult("Function not found: " + identifier);
                }

                switch (view) {
                    case "decompile":
                        return handleDecompileView(program, function, request);
                    case "disassemble":
                        return handleDisassembleView(program, function);
                    case "info":
                        return handleInfoView(program, function);
                    case "calls":
                        return handleCallsView(program, function);
                    default:
                        return createErrorResult("Invalid view mode: " + view);
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in get_function", e);
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
        boolean includeCallers = getOptionalBoolean(request, "include_callers", false);
        boolean includeCallees = getOptionalBoolean(request, "include_callees", false);
        boolean includeComments = getOptionalBoolean(request, "include_comments", false);
        boolean includeIncomingReferences = getOptionalBoolean(request, "include_incoming_references", true);
        boolean includeReferenceContext = getOptionalBoolean(request, "include_reference_context", true);

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
        for (int i = 0; i < function.getLocalVariables().length; i++) {
            var local = function.getLocalVariables()[i];
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
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);
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
                            "Showing first %d of %d references. Use 'get_references' tool with target='%s' and mode='to' to see all references.",
                            maxIncomingRefs, totalRefCount, function.getName()
                        ));
                    }
                }
            }

            // Just return ranged decompilation (includeDisassembly not used in get_function view='decompile')
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
}
