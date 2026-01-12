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
package reva.tools.decompiler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.regex.Matcher;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.UndefinedFunction;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.DataTypeParserUtil;
import reva.util.DecompilationContextUtil;
import reva.util.DecompilationDiffUtil;
import reva.util.DecompilationReadTracker;
import reva.util.DebugLogger;
import reva.util.RevaInternalServiceRegistry;

/**
 * Tool provider for function decompilation operations.
 */
public class DecompilerToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public DecompilerToolProvider(McpSyncServer server) {
        super(server);
    }

    /**
     * Clean up read tracking entries when a program is closed.
     */
    @Override
    public void programClosed(Program program) {
        super.programClosed(program);

        String programPath = program.getDomainFile().getPathname();

        // Remove read tracking entries for the closed program using shared tracker
        int removed = DecompilationReadTracker.clearProgramEntries(programPath);

        if (removed > 0) {
            logInfo("DecompilerToolProvider: Cleared " + removed +
                " read tracking entries for closed program: " + programPath);
        }
    }

    @Override
    public void registerTools() {
    }

    /**
     * Creates a TaskMonitor with timeout configured from settings
     * @return TaskMonitor with timeout from configuration
     */
    private TaskMonitor createTimeoutMonitor() {
        ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
        int timeoutSeconds = configManager.getDecompilerTimeoutSeconds();
        return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
    }

    private boolean isTimedOut(TaskMonitor monitor) {
        return monitor.isCancelled();
    }

    private int getTimeoutSeconds() {
        return RevaInternalServiceRegistry.getService(ConfigManager.class).getDecompilerTimeoutSeconds();
    }

    // ============================================================================
    // Helper Infrastructure for Decompiler Operations
    // ============================================================================

    /** Maximum callers to include in get-decompilation response */
    private static final int MAX_CALLERS_IN_DECOMPILATION = 50;

    /** Maximum callees to include in get-decompilation response */
    private static final int MAX_CALLEES_IN_DECOMPILATION = 50;

    /** Check timeout every N instructions during reference counting */
    private static final int TIMEOUT_CHECK_INSTRUCTION_INTERVAL = 100;

    /** Check timeout every N references during reference counting */
    private static final int TIMEOUT_CHECK_REFERENCE_INTERVAL = 50;

    /** Map of Ghidra comment types to their string names for JSON output */
    private static final Map<CommentType, String> COMMENT_TYPE_NAMES = Map.of(
        CommentType.PRE, "pre",
        CommentType.EOL, "eol",
        CommentType.POST, "post",
        CommentType.PLATE, "plate",
        CommentType.REPEATABLE, "repeatable"
    );

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
     * Functional interface for processing high-level symbols during variable iteration.
     */
    @FunctionalInterface
    private interface SymbolProcessor {
        /**
         * Process a single symbol.
         * @param symbol The high-level symbol to process
         * @return true if processing was successful and changed something, false otherwise
         * @throws DuplicateNameException if a name conflict occurs
         * @throws InvalidInputException if the input is invalid
         */
        boolean process(HighSymbol symbol) throws DuplicateNameException, InvalidInputException;
    }

    /**
     * Creates and configures a DecompInterface for standard decompilation operations.
     * The caller is responsible for disposing the decompiler in a finally block.
     *
     * @param program The program to decompile
     * @param toolName The name of the tool (for logging)
     * @return A configured and initialized DecompInterface, or null if initialization failed
     */
    private DecompInterface createConfiguredDecompiler(Program program, String toolName) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            logError(toolName + ": Failed to initialize decompiler for " + program.getName());
            decompiler.dispose();
            return null;
        }
        return decompiler;
    }

    /**
     * Decompiles a function with timeout handling and consistent error reporting.
     *
     * @param decompiler The initialized decompiler to use
     * @param function The function to decompile
     * @param toolName The name of the tool (for logging)
     * @return DecompilationAttempt containing either the results or an error message
     */
    private DecompilationAttempt decompileFunctionSafely(
            DecompInterface decompiler,
            Function function,
            String toolName) {
        TaskMonitor timeoutMonitor = createTimeoutMonitor();
        DecompileResults results = decompiler.decompileFunction(function, 0, timeoutMonitor);

        if (isTimedOut(timeoutMonitor)) {
            String msg = "Decompilation timed out after " + getTimeoutSeconds() + " seconds";
            logError(toolName + ": " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        if (!results.decompileCompleted()) {
            String msg = "Decompilation failed: " + results.getErrorMessage();
            logError(toolName + ": " + msg + " for " + function.getName());
            return DecompilationAttempt.failure(msg);
        }

        return DecompilationAttempt.success(results);
    }

    /**
     * Gets updated decompilation after modifications and creates a diff against the original.
     *
     * @param program The program containing the function
     * @param function The function to re-decompile
     * @param beforeDecompilation The original decompilation text to compare against
     * @param toolName The name of the tool (for logging)
     * @return Map containing diff results or error information
     */
    private Map<String, Object> getDecompilationDiff(
            Program program,
            Function function,
            String beforeDecompilation,
            String toolName) {
        Map<String, Object> result = new HashMap<>();

        DecompInterface newDecompiler = createConfiguredDecompiler(program, toolName + "-diff");
        if (newDecompiler == null) {
            result.put("decompilationError", "Failed to initialize decompiler for diff");
            return result;
        }

        try {
            DecompilationAttempt attempt = decompileFunctionSafely(newDecompiler, function, toolName + "-diff");
            if (!attempt.success()) {
                result.put("decompilationError", attempt.errorMessage());
                return result;
            }

            String afterDecompilation = attempt.results().getDecompiledFunction().getC();
            DecompilationDiffUtil.DiffResult diff =
                DecompilationDiffUtil.createDiff(beforeDecompilation, afterDecompilation);

            if (diff.hasChanges()) {
                result.put("changes", DecompilationDiffUtil.toMap(diff));
            } else {
                result.put("changes", Map.of(
                    "hasChanges", false,
                    "summary", "No changes detected in decompilation"
                ));
            }
        } catch (Exception e) {
            logError(toolName + "-diff: Error during diff decompilation", e);
            result.put("decompilationError", "Exception during decompilation: " + e.getMessage());
        } finally {
            newDecompiler.dispose();
        }

        return result;
    }

    /**
     * Processes all variables (local and global) in a high function using the provided processor.
     *
     * @param highFunction The high function containing the variables
     * @param processor The processor to apply to each symbol
     * @param toolName The name of the tool (for logging)
     * @return The number of symbols successfully processed
     */
    private int processAllVariables(HighFunction highFunction, SymbolProcessor processor, String toolName) {
        int processedCount = 0;

        // Process local variables
        Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
        while (localVars.hasNext()) {
            HighSymbol symbol = localVars.next();
            try {
                if (processor.process(symbol)) {
                    processedCount++;
                }
            } catch (DuplicateNameException | InvalidInputException e) {
                logError(toolName + ": Failed to process local variable " + symbol.getName(), e);
            }
        }

        // Process global variables
        Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
        while (globalVars.hasNext()) {
            HighSymbol symbol = globalVars.next();
            try {
                if (processor.process(symbol)) {
                    processedCount++;
                }
            } catch (DuplicateNameException | InvalidInputException e) {
                logError(toolName + ": Failed to process global variable " + symbol.getName(), e);
            }
        }

        return processedCount;
    }

    /**
     * Finds the address corresponding to a line number in decompiled code.
     *
     * @param program The program
     * @param clangLines The decompiled code lines
     * @param lineNumber The line number to find (1-based)
     * @return The address for the line, or null if not found
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
     * Processes variable data type changes for all variables in a high function.
     * This method handles the specific logic for data type changes including error collection.
     *
     * @param highFunction The high function containing the variables
     * @param mappings Map of variable names to new data type strings
     * @param archiveName Optional archive name for data type lookup
     * @param errors List to collect error messages
     * @param toolName The name of the tool (for logging)
     * @return The number of variables successfully changed
     */
    private int processVariableDataTypeChanges(
            HighFunction highFunction,
            Map<String, String> mappings,
            String archiveName,
            List<String> errors,
            String toolName) {
        int changedCount = 0;

        // Process local variables
        Iterator<HighSymbol> localVars = highFunction.getLocalSymbolMap().getSymbols();
        while (localVars.hasNext()) {
            HighSymbol symbol = localVars.next();
            if (processDataTypeChange(symbol, mappings, archiveName, errors, toolName)) {
                changedCount++;
            }
        }

        // Process global variables
        Iterator<HighSymbol> globalVars = highFunction.getGlobalSymbolMap().getSymbols();
        while (globalVars.hasNext()) {
            HighSymbol symbol = globalVars.next();
            if (processDataTypeChange(symbol, mappings, archiveName, errors, toolName)) {
                changedCount++;
            }
        }

        return changedCount;
    }

    /**
     * Processes a single data type change for a symbol.
     *
     * @param symbol The symbol to process
     * @param mappings Map of variable names to new data type strings
     * @param archiveName Optional archive name for data type lookup
     * @param errors List to collect error messages
     * @param toolName The name of the tool (for logging)
     * @return true if the data type was changed, false otherwise
     */
    private boolean processDataTypeChange(
            HighSymbol symbol,
            Map<String, String> mappings,
            String archiveName,
            List<String> errors,
            String toolName) {
        String varName = symbol.getName();
        String newDataTypeString = mappings.get(varName);

        if (newDataTypeString == null) {
            return false;
        }

        try {
            DataType newDataType = DataTypeParserUtil.parseDataTypeObjectFromString(
                newDataTypeString, archiveName);

            if (newDataType == null) {
                errors.add("Could not find data type: " + newDataTypeString + " for variable " + varName);
                return false;
            }

            HighFunctionDBUtil.updateDBVariable(symbol, null, newDataType, SourceType.USER_DEFINED);
            logInfo(toolName + ": Changed data type of variable " + varName + " to " + newDataTypeString);
            return true;
        } catch (DuplicateNameException | InvalidInputException e) {
            errors.add("Failed to change data type of variable " + varName + " to " + newDataTypeString + ": " + e.getMessage());
        } catch (Exception e) {
            errors.add("Error parsing data type " + newDataTypeString + " for variable " + varName + ": " + e.getMessage());
        }

        return false;
    }

    /**
     * Result of counting call references with timeout handling.
     */
    private record CallCountResult(
        Map<Address, Integer> callCounts,
        boolean timedOut
    ) {}

    /**
     * Count call references for a function (either callers or callees) with timeout handling.
     * This method handles the iteration over instructions and references consistently.
     *
     * @param program The program
     * @param function The function to count calls for
     * @param countCallers true to count callers (references TO this function),
     *                     false to count callees (references FROM this function)
     * @return CallCountResult containing the counts and timeout status
     */
    private CallCountResult countCallsWithTimeout(Program program, Function function, boolean countCallers) {
        TaskMonitor monitor = createTimeoutMonitor();
        Map<Address, Integer> callCounts = new HashMap<>();
        boolean timedOut = false;

        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        Listing listing = program.getListing();
        AddressSetView functionBody = function.getBody();

        int instrCount = 0;
        int refCount = 0;

        for (Instruction instr : listing.getInstructions(functionBody, true)) {
            // Check timeout periodically on instruction boundary
            if (++instrCount % TIMEOUT_CHECK_INSTRUCTION_INTERVAL == 0 && monitor.isCancelled()) {
                timedOut = true;
                break;
            }

            if (countCallers) {
                // For callers: get references TO each instruction in this function
                ReferenceIterator refsTo = refManager.getReferencesTo(instr.getAddress());
                while (refsTo.hasNext()) {
                    // Check timeout in inner loop for addresses with many references
                    if (++refCount % TIMEOUT_CHECK_REFERENCE_INTERVAL == 0 && monitor.isCancelled()) {
                        timedOut = true;
                        break;
                    }
                    Reference ref = refsTo.next();
                    if (ref.getReferenceType().isCall()) {
                        Function caller = funcManager.getFunctionContaining(ref.getFromAddress());
                        if (caller != null) {
                            callCounts.merge(caller.getEntryPoint(), 1, Integer::sum);
                        }
                    }
                }
                if (timedOut) break;
            } else {
                // For callees: get references FROM each instruction in this function
                // No inner-loop timeout check needed here because getReferencesFrom() typically
                // returns very few references per instruction (usually 0-1 call targets),
                // unlike getReferencesTo() which can return thousands for popular functions
                Reference[] refsFrom = instr.getReferencesFrom();
                for (Reference ref : refsFrom) {
                    if (ref.getReferenceType().isCall()) {
                        // Resolve to function entry point (ref.getToAddress() may be inside function)
                        Function callee = funcManager.getFunctionAt(ref.getToAddress());
                        if (callee == null) {
                            // Try to find containing function if not at entry point
                            callee = funcManager.getFunctionContaining(ref.getToAddress());
                        }
                        if (callee != null) {
                            callCounts.merge(callee.getEntryPoint(), 1, Integer::sum);
                        }
                    }
                }
            }
        }

        return new CallCountResult(callCounts, timedOut);
    }

    /**
     * Build a list of caller/callee info maps for the result.
     *
     * @param functions The set of functions (callers or callees)
     * @param callCounts Map of entry point addresses to call counts
     * @param maxCount Maximum number to include
     * @return List of function info maps
     */
    private List<Map<String, Object>> buildCallListInfo(
            Set<Function> functions,
            Map<Address, Integer> callCounts,
            int maxCount) {
        List<Map<String, Object>> resultList = new ArrayList<>();
        int count = 0;

        for (Function func : functions) {
            if (count >= maxCount) break;

            Map<String, Object> funcInfo = new HashMap<>();
            funcInfo.put("name", func.getName());
            funcInfo.put("address", AddressUtil.formatAddress(func.getEntryPoint()));
            funcInfo.put("signature", func.getSignature().getPrototypeString());
            funcInfo.put("callCount", callCounts.getOrDefault(func.getEntryPoint(), 0));

            resultList.add(funcInfo);
            count++;
        }

        return resultList;
    }

    // ============================================================================
    // Helper Infrastructure (kept for potential future use)
    // ============================================================================
}
