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
package reva.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

/**
 * Utility class for providing smart suggestions based on program context.
 * Provides heuristics-based suggestions for comment types, function names,
 * variable names, etc. Uses a canonical naming grammar and semantic analysis
 * to produce high-quality, predictable function names.
 */
public class SmartSuggestionsUtil {

    // ========================================================================
    // Canonical naming configuration and patterns
    // ========================================================================

    /**
     * Canonical verb set for function names.
     * We try hard to stay inside this vocabulary to keep names predictable.
     * This list serves as documentation of preferred verbs; the inference
     * logic maps API calls and patterns to these canonical verbs.
     */
    @SuppressWarnings("unused")
    private static final List<String> CANONICAL_VERBS = List.of(
        "allocate",
        "apply",
        "calculate",
        "check",
        "close",
        "compute",
        "convert",
        "copy",
        "create",
        "decode",
        "destroy",
        "dispatch",
        "encode",
        "get",
        "handle",
        "init",
        "load",
        "log",
        "move",
        "open",
        "parse",
        "query",
        "read",
        "release",
        "resolve",
        "set",
        "update",
        "validate",
        "write"
    );

    // Common API patterns for function name suggestions -> coarse categories
    private static final Map<String, String> API_PATTERNS = new HashMap<>();
    static {
        API_PATTERNS.put("CreateFile", "file");
        API_PATTERNS.put("ReadFile", "file");
        API_PATTERNS.put("WriteFile", "file");
        API_PATTERNS.put("CloseHandle", "handle");
        API_PATTERNS.put("RegOpenKey", "registry");
        API_PATTERNS.put("RegQueryValue", "registry");
        API_PATTERNS.put("InternetOpen", "network");
        API_PATTERNS.put("HttpSendRequest", "http");
        API_PATTERNS.put("CryptAcquireContext", "crypto");
        API_PATTERNS.put("CryptEncrypt", "crypto");
        API_PATTERNS.put("CryptDecrypt", "crypto");
        API_PATTERNS.put("malloc", "memory");
        API_PATTERNS.put("free", "memory");
        API_PATTERNS.put("strcpy", "string");
        API_PATTERNS.put("strcmp", "string");
    }

    // Data type to preferred variable base names
    private static final Map<String, String> TYPE_NAME_PATTERNS = new HashMap<>();
    static {
        TYPE_NAME_PATTERNS.put("char*", "buffer");
        TYPE_NAME_PATTERNS.put("char[]", "buffer");
        TYPE_NAME_PATTERNS.put("wchar_t*", "wbuffer");
        TYPE_NAME_PATTERNS.put("string", "str");
        TYPE_NAME_PATTERNS.put("int", "value");
        TYPE_NAME_PATTERNS.put("uint", "value");
        TYPE_NAME_PATTERNS.put("unsigned int", "value");
        TYPE_NAME_PATTERNS.put("long", "value");
        TYPE_NAME_PATTERNS.put("short", "value");
        TYPE_NAME_PATTERNS.put("bool", "flag");
        TYPE_NAME_PATTERNS.put("boolean", "flag");
        TYPE_NAME_PATTERNS.put("void*", "ptr");
        TYPE_NAME_PATTERNS.put("int*", "array");
        TYPE_NAME_PATTERNS.put("float", "value");
        TYPE_NAME_PATTERNS.put("double", "value");
        TYPE_NAME_PATTERNS.put("struct", "item");
        TYPE_NAME_PATTERNS.put("FILE*", "file");
        TYPE_NAME_PATTERNS.put("HANDLE", "handle");
        TYPE_NAME_PATTERNS.put("HWND", "window");
        TYPE_NAME_PATTERNS.put("SOCKET", "socket");
    }

    // Library to tag mappings
    private static final Map<String, List<String>> LIBRARY_TAG_PATTERNS = new HashMap<>();
    static {
        LIBRARY_TAG_PATTERNS.put("kernel32", List.of("windows_api", "system"));
        LIBRARY_TAG_PATTERNS.put("user32", List.of("windows_api", "ui"));
        LIBRARY_TAG_PATTERNS.put("advapi32", List.of("windows_api", "registry", "security"));
        LIBRARY_TAG_PATTERNS.put("ws2_32", List.of("network", "windows_api"));
        LIBRARY_TAG_PATTERNS.put("wininet", List.of("network", "http"));
        LIBRARY_TAG_PATTERNS.put("crypt32", List.of("crypto", "security"));
        LIBRARY_TAG_PATTERNS.put("ntdll", List.of("windows_api", "system", "low_level"));
        LIBRARY_TAG_PATTERNS.put("msvcrt", List.of("c_runtime", "standard_library"));
        LIBRARY_TAG_PATTERNS.put("libc", List.of("c_runtime", "standard_library"));
        LIBRARY_TAG_PATTERNS.put("libssl", List.of("crypto", "network"));
        LIBRARY_TAG_PATTERNS.put("libcrypto", List.of("crypto", "security"));
    }

    // String pattern to tag mappings
    private static final Map<Pattern, List<String>> STRING_TAG_PATTERNS = new HashMap<>();
    static {
        STRING_TAG_PATTERNS.put(Pattern.compile("https?://", Pattern.CASE_INSENSITIVE), List.of("network", "http"));
        STRING_TAG_PATTERNS.put(Pattern.compile("ftp://", Pattern.CASE_INSENSITIVE), List.of("network", "ftp"));
        STRING_TAG_PATTERNS.put(Pattern.compile("\\.[a-z]{2,4}$", Pattern.CASE_INSENSITIVE), List.of("file_operations"));
        STRING_TAG_PATTERNS.put(Pattern.compile("password|secret|key|token", Pattern.CASE_INSENSITIVE), List.of("security", "authentication"));
        STRING_TAG_PATTERNS.put(Pattern.compile("encrypt|decrypt|cipher", Pattern.CASE_INSENSITIVE), List.of("crypto"));
        STRING_TAG_PATTERNS.put(Pattern.compile("md5|sha1|sha256|aes|des", Pattern.CASE_INSENSITIVE), List.of("crypto", "hashing"));
        STRING_TAG_PATTERNS.put(Pattern.compile("registry|reg_", Pattern.CASE_INSENSITIVE), List.of("registry", "windows_api"));
        STRING_TAG_PATTERNS.put(Pattern.compile("createfile|readfile|writefile", Pattern.CASE_INSENSITIVE), List.of("file_operations"));
    }

    // API to tag mappings
    private static final Map<String, List<String>> API_TAG_PATTERNS = new HashMap<>();
    static {
        API_TAG_PATTERNS.put("CreateFile", List.of("file_operations", "io"));
        API_TAG_PATTERNS.put("ReadFile", List.of("file_operations", "io"));
        API_TAG_PATTERNS.put("WriteFile", List.of("file_operations", "io"));
        API_TAG_PATTERNS.put("CryptAcquireContext", List.of("crypto", "security"));
        API_TAG_PATTERNS.put("CryptEncrypt", List.of("crypto", "security"));
        API_TAG_PATTERNS.put("CryptDecrypt", List.of("crypto", "security"));
        API_TAG_PATTERNS.put("InternetOpen", List.of("network", "http"));
        API_TAG_PATTERNS.put("HttpSendRequest", List.of("network", "http"));
        API_TAG_PATTERNS.put("RegOpenKey", List.of("registry", "windows_api"));
        API_TAG_PATTERNS.put("RegQueryValue", List.of("registry", "windows_api"));
        API_TAG_PATTERNS.put("malloc", List.of("memory_operations"));
        API_TAG_PATTERNS.put("free", List.of("memory_operations"));
        API_TAG_PATTERNS.put("strcpy", List.of("string_operations"));
        API_TAG_PATTERNS.put("strcmp", List.of("string_operations"));
    }

    // ========================================================================
    // Internal semantic model
    // ========================================================================

    private static class SemanticInfo {
        Program program;
        Function function;

        List<String> apiCalls = new ArrayList<>();
        List<String> nearbyStrings = new ArrayList<>();
        Set<String> inferredTags = new HashSet<>();

        int callerCount;
        int calleeCount;
        int parameterCount;

        String returnTypeName;
        boolean returnsValue;
        boolean isLeaf;
        boolean hasLoopLikeBranches;
        boolean hasSwitch;
        boolean isThunk;
        boolean isLikelyDispatcher;
        boolean isLikelyInitializer;
        boolean isLikelyCleanup;
    }

    // ========================================================================
    // Comment type suggestion
    // ========================================================================

    /**
     * Suggest comment type based on address context
     *
     * @param program The program
     * @param address The address to analyze
     * @return Suggested comment type ("pre", "eol", "post", "plate",
     * "repeatable") with confidence and reason
     */
    public static Map<String, Object> suggestCommentType(Program program, Address address) {
        Map<String, Object> suggestion = new HashMap<>();

        if (address == null || program == null) {
            suggestion.put("commentType", "eol");
            suggestion.put("confidence", 0.5);
            suggestion.put("reason", "Default suggestion");
            return suggestion;
        }

        Listing listing = program.getListing();
        FunctionManager funcManager = program.getFunctionManager();

        // Function entry point -> plate header
        Function function = funcManager.getFunctionContaining(address);
        if (function != null && function.getEntryPoint().equals(address)) {
            suggestion.put("commentType", "plate");
            suggestion.put("confidence", 0.9);
            suggestion.put("reason", "Address is a function entry point - plate comments are typically used for function headers");
            return suggestion;
        }

        // Data -> pre (structure/field context)
        Data data = listing.getDataAt(address);
        if (data != null) {
            suggestion.put("commentType", "pre");
            suggestion.put("confidence", 0.8);
            suggestion.put("reason", "Address contains data - pre comments are typically used for data structures");
            return suggestion;
        }

        // Instruction -> eol
        Instruction instruction = listing.getInstructionAt(address);
        if (instruction != null) {
            if (instruction.getFlowType().isCall()) {
                suggestion.put("commentType", "eol");
                suggestion.put("confidence", 0.85);
                suggestion.put("reason", "Address is a call instruction - eol comments are typically used for inline call annotations");
            } else {
                suggestion.put("commentType", "eol");
                suggestion.put("confidence", 0.7);
                suggestion.put("reason", "Address is an instruction - eol comments are the most common for code annotations");
            }
            return suggestion;
        }

        suggestion.put("commentType", "eol");
        suggestion.put("confidence", 0.6);
        suggestion.put("reason", "Default suggestion for code addresses");
        return suggestion;
    }

    // ========================================================================
    // Function name suggestions (canonical and semantics-driven)
    // ========================================================================

    /**
     * Suggest function names based on rich semantic context:
     *  - API calls
     *  - strings
     *  - callers/callees
     *  - control flow (loops, switches, dispatchers)
     *  - parameters and return types
     *  Names follow a canonical grammar: verb_object[_qualifier]
     *
     * @param program  The program
     * @param function The function to analyze
     * @return List of suggested names with confidence scores and reasons
     */
    public static List<Map<String, Object>> suggestFunctionNames(Program program, Function function) {
        List<Map<String, Object>> suggestions = new ArrayList<>();

        if (program == null || function == null) {
            return suggestions;
        }

        SemanticInfo info = analyzeFunctionSemantics(program, function);

        // Collect candidate names with reasons and base scores
        List<CandidateName> candidates = new ArrayList<>();

        // Strategy 1: canonical verb/object/qualifier synthesis
        CandidateName canonical = buildCanonicalNameCandidate(info);
        if (canonical != null) {
            candidates.add(canonical);
        }

        // Strategy 2: string-derived names (but normalized into canonical grammar)
        candidates.addAll(buildStringBasedCandidates(info));

        // Strategy 3: API category based names
        candidates.addAll(buildApiBasedCandidates(info));

        // Strategy 4: role-based names (dispatcher, initializer, cleanup, helper)
        candidates.addAll(buildRoleBasedCandidates(info));

        // Strategy 5: low-confidence fallbacks if nothing else is strong
        if (candidates.isEmpty()) {
            CandidateName fallback = new CandidateName();
            fallback.name = "func_" + Long.toHexString(function.getEntryPoint().getOffset());
            fallback.score = 0.4;
            fallback.reasons.add("Fallback: no strong semantic signals; naming by address");
            candidates.add(fallback);
        }

        // Deduplicate, normalize, and sort by score
        candidates = deduplicateCandidates(candidates);
        candidates.sort((a, b) -> Double.compare(b.score, a.score));

        // Convert to public result format
        for (CandidateName c : candidates) {
            Map<String, Object> sug = new HashMap<>();
            sug.put("name", c.name);
            sug.put("confidence", clamp(c.score, 0.0, 1.0));
            sug.put("reasons", new ArrayList<>(c.reasons));
            suggestions.add(sug);
        }

        return suggestions;
    }

    // ========================================================================
    // Variable name suggestion
    // ========================================================================

    /**
     * Suggest variable names based on data type and usage context
     *
     * @param program  The program
     * @param function The function containing the variable
     * @param dataType The data type string
     * @return Suggested variable name with confidence and reason
     */
    public static Map<String, Object> suggestVariableName(Program program, Function function, String dataType) {
        Map<String, Object> suggestion = new HashMap<>();

        if (dataType == null || dataType.isEmpty()) {
            suggestion.put("name", "var");
            suggestion.put("confidence", 0.3);
            suggestion.put("reason", "Default suggestion");
            return suggestion;
        }

        // Normalize data type
        String normalizedType = dataType.toLowerCase().trim();

        // 1. Type-based base names
        for (Map.Entry<String, String> entry : TYPE_NAME_PATTERNS.entrySet()) {
            if (normalizedType.contains(entry.getKey().toLowerCase())) {
                String base = entry.getValue();
                String contextualName = applyFunctionContextToVariableName(base, function);
                suggestion.put("name", contextualName);
                suggestion.put("confidence", 0.75);
                suggestion.put("reason", "Based on data type pattern: " + entry.getKey());
                return suggestion;
            }
        }

        // 2. Pointer types
        if (normalizedType.contains("*") || normalizedType.contains("ptr")) {
            String base = "ptr";
            String contextualName = applyFunctionContextToVariableName(base, function);
            suggestion.put("name", contextualName);
            suggestion.put("confidence", 0.7);
            suggestion.put("reason", "Pointer type detected");
            return suggestion;
        }

        // 3. Array types
        if (normalizedType.contains("[") || normalizedType.contains("array")) {
            String base = "array";
            String contextualName = applyFunctionContextToVariableName(base, function);
            suggestion.put("name", contextualName);
            suggestion.put("confidence", 0.7);
            suggestion.put("reason", "Array type detected");
            return suggestion;
        }

        // 4. Fallback: derive from raw type text
        String base = camelToSnake(dataType).replace(" ", "_");
        if (base.isEmpty()) {
            base = "value";
        }
        String contextualName = applyFunctionContextToVariableName(base, function);
        suggestion.put("name", contextualName);
        suggestion.put("confidence", 0.55);
        suggestion.put("reason", "Generic suggestion for type: " + dataType);
        return suggestion;
    }

    // ========================================================================
    // Function tag suggestions (mostly unchanged, but using helper semantics)
    // ========================================================================

    /**
     * Suggest function tags based on function characteristics, strings, and API calls
     *
     * @param program  The program
     * @param function The function to analyze
     * @return List of suggested tags with confidence scores and reasons
     */
    public static List<Map<String, Object>> suggestFunctionTags(Program program, Function function) {
        List<Map<String, Object>> suggestions = new ArrayList<>();
        Map<String, Double> tagScores = new HashMap<>();

        if (program == null || function == null) {
            return suggestions;
        }

        // Strategy 1: Check API calls
        List<String> apiCalls = findAPICalls(program, function);
        for (String api : apiCalls) {
            List<String> tags = API_TAG_PATTERNS.get(api);
            if (tags != null) {
                for (String tag : tags) {
                    tagScores.put(tag, tagScores.getOrDefault(tag, 0.0) + 0.8);
                }
            }
        }

        // Strategy 2: Check library imports
        String libraryName = findFunctionLibrary(program, function);
        if (libraryName != null) {
            List<String> tags = LIBRARY_TAG_PATTERNS.get(libraryName.toLowerCase());
            if (tags != null) {
                for (String tag : tags) {
                    tagScores.put(tag, tagScores.getOrDefault(tag, 0.0) + 0.75);
                }
            }
        }

        // Strategy 3: Check string references for patterns
        List<String> nearbyStrings = findNearbyStrings(program, function);
        for (String str : nearbyStrings) {
            for (Map.Entry<Pattern, List<String>> entry : STRING_TAG_PATTERNS.entrySet()) {
                if (entry.getKey().matcher(str).find()) {
                    for (String tag : entry.getValue()) {
                        tagScores.put(tag, tagScores.getOrDefault(tag, 0.0) + 0.7);
                    }
                }
            }
        }

        // Strategy 4: Check function characteristics
        if (hasCryptoOperations(program, function)) {
            tagScores.put("crypto", tagScores.getOrDefault("crypto", 0.0) + 0.85);
        }
        if (hasNetworkOperations(program, function)) {
            tagScores.put("network", tagScores.getOrDefault("network", 0.0) + 0.85);
        }
        if (hasFileOperations(program, function)) {
            tagScores.put("file_operations", tagScores.getOrDefault("file_operations", 0.0) + 0.85);
        }

        // Convert scores to suggestions
        for (Map.Entry<String, Double> entry : tagScores.entrySet()) {
            Map<String, Object> sug = new HashMap<>();
            sug.put("tag", entry.getKey());
            double confidence = Math.min(1.0, entry.getValue());
            sug.put("confidence", confidence);
            sug.put("reasons", generateTagReasons(program, function, entry.getKey()));
            suggestions.add(sug);
        }

        // Sort by confidence
        suggestions.sort((a, b) -> {
            double confA = (Double) a.get("confidence");
            double confB = (Double) b.get("confidence");
            return Double.compare(confB, confA);
        });

        return suggestions;
    }

    // ========================================================================
    // Comment text suggestion
    // ========================================================================

    /**
     * Suggest recommended comment text based on address context
     *
     * @param program The program
     * @param address The address to analyze
     * @return Suggested comment text with confidence
     */
    public static Map<String, Object> suggestCommentText(Program program, Address address) {
        Map<String, Object> suggestion = new HashMap<>();

        if (address == null || program == null) {
            suggestion.put("text", "");
            suggestion.put("confidence", 0.0);
            return suggestion;
        }

        FunctionManager funcManager = program.getFunctionManager();
        Function function = funcManager.getFunctionContaining(address);

        // If it's a function entry point, suggest function header comment
        if (function != null && function.getEntryPoint().equals(address)) {
            String funcName = function.getName();
            int paramCount = function.getParameterCount();

            StringBuilder comment = new StringBuilder();
            comment.append("Function: ").append(funcName);
            if (paramCount > 0) {
                comment.append(" (").append(paramCount).append(" parameter");
                if (paramCount > 1) {
                    comment.append("s");
                }
                comment.append(")");
            }

            suggestion.put("text", comment.toString());
            suggestion.put("confidence", 0.8);
            suggestion.put("reason", "Function entry point - suggests function header comment");
            return suggestion;
        }

        // Data structure comment
        Data data = program.getListing().getDataAt(address);
        if (data != null) {
            String dataType = data.getDataType().getName();
            suggestion.put("text", "Data: " + dataType);
            suggestion.put("confidence", 0.7);
            suggestion.put("reason", "Data address - suggests data structure comment");
            return suggestion;
        }

        suggestion.put("text", "");
        suggestion.put("confidence", 0.3);
        suggestion.put("reason", "No specific context for comment suggestion");
        return suggestion;
    }

    // ========================================================================
    // Data type suggestion
    // ========================================================================

    /**
     * Suggest data type based on usage patterns and context
     *
     * @param program  The program
     * @param function The function containing the variable (may be null)
     * @param address  The address of the data/variable
     * @return Suggested data type with confidence
     */
    public static Map<String, Object> suggestDataType(Program program, Function function, Address address) {
        Map<String, Object> suggestion = new HashMap<>();

        if (program == null || address == null) {
            suggestion.put("dataType", "void*");
            suggestion.put("confidence", 0.3);
            return suggestion;
        }

        // 1. Existing defined type takes precedence
        Data data = program.getListing().getDataAt(address);
        if (data != null) {
            String currentType = data.getDataType().getName();
            suggestion.put("dataType", currentType);
            suggestion.put("confidence", 0.9);
            suggestion.put("reason", "Data type already defined at address");
            return suggestion;
        }

        // 2. Check for string-like usage in the function context
        if (function != null) {
            List<String> nearbyStrings = findNearbyStrings(program, function);
            if (!nearbyStrings.isEmpty()) {
                suggestion.put("dataType", "char*");
                suggestion.put("confidence", 0.75);
                suggestion.put("reason", "Nearby string references suggest char* type");
                return suggestion;
            }
        }

        // 3. Heuristic: look at references to this address (read vs write)
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refIter = refManager.getReferencesTo(address);
        boolean isWritten = false;
        boolean isRead = false;
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isWrite()) {
                isWritten = true;
            }
            if (ref.getReferenceType().isRead()) {
                isRead = true;
            }
        }

        if (isRead && !isWritten) {
            suggestion.put("dataType", "const int");
            suggestion.put("confidence", 0.6);
            suggestion.put("reason", "Referenced as read-only; likely constant scalar");
            return suggestion;
        }

        if (isWritten && !isRead) {
            suggestion.put("dataType", "int");
            suggestion.put("confidence", 0.55);
            suggestion.put("reason", "Primarily written; likely mutable scalar");
            return suggestion;
        }

        suggestion.put("dataType", "int");
        suggestion.put("confidence", 0.5);
        suggestion.put("reason", "Default suggestion - analyze usage further for better type");
        return suggestion;
    }

    // ========================================================================
    // Internal: semantic analysis and candidate building
    // ========================================================================

    private static SemanticInfo analyzeFunctionSemantics(Program program, Function function) {
        SemanticInfo info = new SemanticInfo();
        info.program = program;
        info.function = function;

        info.apiCalls = findAPICalls(program, function);
        info.nearbyStrings = findNearbyStrings(program, function);
        info.parameterCount = function.getParameterCount();
        info.returnTypeName = function.getReturnType() != null ? function.getReturnType().getName() : null;
        info.returnsValue = info.returnTypeName != null && !"void".equalsIgnoreCase(info.returnTypeName);

        // callers / callees
        info.calleeCount = function.getCalledFunctions(null).size();
        info.callerCount = function.getCallingFunctions(null).size();
        info.isLeaf = (info.calleeCount == 0);

        // Very simple control-flow heuristics
        analyzeControlFlow(info);

        // Role heuristics
        inferRoleHeuristics(info);

        // Tags from API and string patterns
        info.inferredTags.addAll(inferTagsFromApis(info.apiCalls));
        info.inferredTags.addAll(inferTagsFromStrings(info.nearbyStrings));

        return info;
    }

    private static void analyzeControlFlow(SemanticInfo info) {
        Listing listing = info.program.getListing();
        AddressSetView body = info.function.getBody();

        boolean hasBackwardsBranch = false;
        boolean hasSwitch = false;
        boolean maybeThunk = true;

        for (Address addr : body.getAddresses(true)) {
            Instruction instr = listing.getInstructionAt(addr);
            if (instr == null) {
                continue;
            }

            // Check for computed jumps which often indicate switches
            if (instr.getFlowType().isComputed()) {
                hasSwitch = true;
            }

            if (instr.getFlowType().isJump() || instr.getFlowType().isConditional()) {
                for (Reference ref : info.program.getReferenceManager().getReferencesFrom(addr)) {
                    Address to = ref.getToAddress();
                    if (to != null && to.compareTo(addr) < 0) {
                        hasBackwardsBranch = true;
                    }
                }
            }

            // Thunk detection: if we see more than a couple real instructions,
            // stop treating it as a thunk
            String mnemonic = instr.getMnemonicString().toLowerCase();
            // Count non-trivial instructions (not just jumps, nops, pushes, pops, rets)
            if (!mnemonic.equals("jmp") && !mnemonic.equals("nop") && !mnemonic.equals("push") &&
                !mnemonic.equals("pop") && !mnemonic.equals("ret") && !mnemonic.equals("retn") &&
                !mnemonic.equals("call")) {
                maybeThunk = false;
            }
        }

        info.hasLoopLikeBranches = hasBackwardsBranch;
        info.hasSwitch = hasSwitch;
        info.isThunk = maybeThunk && info.calleeCount == 1;

        // Dispatcher heuristic: switch + many callees
        info.isLikelyDispatcher = info.hasSwitch && info.calleeCount > 3;

        // Initializer heuristic: many writes, few callers, often "init" strings
        if (info.callerCount <= 2 && info.calleeCount > 0) {
            for (String s : info.nearbyStrings) {
                String lower = s.toLowerCase();
                if (lower.contains("init") || lower.contains("initialize") || lower.contains("startup")) {
                    info.isLikelyInitializer = true;
                    break;
                }
            }
        }

        // Cleanup heuristic: no return value, few callers, and strings like "destroy"/"cleanup"
        if (!info.returnsValue && info.callerCount <= 2) {
            for (String s : info.nearbyStrings) {
                String lower = s.toLowerCase();
                if (lower.contains("cleanup") || lower.contains("destroy") || lower.contains("shutdown")) {
                    info.isLikelyCleanup = true;
                    break;
                }
            }
        }
    }

    private static void inferRoleHeuristics(SemanticInfo info) {
        // Additional role signals based on API calls
        for (String api : info.apiCalls) {
            String lower = api.toLowerCase();
            if (lower.contains("create") || lower.contains("init") || lower.contains("initialize")) {
                info.isLikelyInitializer = true;
            }
            if (lower.contains("close") || lower.contains("free") || lower.contains("destroy") || lower.contains("cleanup")) {
                info.isLikelyCleanup = true;
            }
        }
    }

    private static Set<String> inferTagsFromApis(List<String> apiCalls) {
        Set<String> tags = new HashSet<>();
        for (String api : apiCalls) {
            List<String> mapped = API_TAG_PATTERNS.get(api);
            if (mapped != null) {
                tags.addAll(mapped);
            }
        }
        return tags;
    }

    private static Set<String> inferTagsFromStrings(List<String> strings) {
        Set<String> tags = new HashSet<>();
        for (String s : strings) {
            for (Map.Entry<Pattern, List<String>> entry : STRING_TAG_PATTERNS.entrySet()) {
                if (entry.getKey().matcher(s).find()) {
                    tags.addAll(entry.getValue());
                }
            }
        }
        return tags;
    }

    // ------------------------------------------------------------------------
    // Candidate name model
    // ------------------------------------------------------------------------

    private static class CandidateName {
        String name;
        double score;
        List<String> reasons = new ArrayList<>();
    }

    private static CandidateName buildCanonicalNameCandidate(SemanticInfo info) {
        String verb = inferVerb(info);
        String object = inferObject(info);
        String qualifier = inferQualifier(info);

        if (verb == null && object == null) {
            return null;
        }

        if (verb == null) {
            verb = "func";
        }
        if (object == null) {
            object = "unknown";
        }

        String baseName = buildCanonicalName(verb, object, qualifier);

        CandidateName c = new CandidateName();
        c.name = baseName;
        c.score = 0.8; // base score; will be adjusted by reasons

        c.reasons.add("Canonical synthesis from control-flow, API calls, and strings");
        c.reasons.add("Verb: " + verb);
        c.reasons.add("Object: " + object);
        if (qualifier != null && !qualifier.isEmpty()) {
            c.reasons.add("Qualifier: " + qualifier);
            c.score += 0.05;
        }

        // Confidence tweaks
        if (info.isLikelyDispatcher) {
            c.score += 0.05;
        }
        if (info.isLikelyInitializer || info.isLikelyCleanup) {
            c.score += 0.05;
        }
        if (info.inferredTags.contains("file_operations") || info.inferredTags.contains("network") || info.inferredTags.contains("crypto")) {
            c.score += 0.05;
        }

        return c;
    }

    private static List<CandidateName> buildStringBasedCandidates(SemanticInfo info) {
        List<CandidateName> result = new ArrayList<>();

        for (String s : info.nearbyStrings) {
            String extracted = extractNameFromString(s);
            if (extracted == null || extracted.isEmpty()) {
                continue;
            }

            // Try to map the extracted string into object/qualifier, using a generic verb
            String object = extracted;
            String verb = inferVerbFromString(extracted);
            if (verb == null) {
                verb = "handle";
            }

            String name = buildCanonicalName(verb, object, null);

            CandidateName c = new CandidateName();
            c.name = name;
            c.score = 0.7;
            c.reasons.add("Derived from nearby string: " + s);
            result.add(c);
        }

        return result;
    }

    private static List<CandidateName> buildApiBasedCandidates(SemanticInfo info) {
        List<CandidateName> result = new ArrayList<>();

        for (String api : info.apiCalls) {
            String category = API_PATTERNS.get(api);
            String canonicalApiName = extractBaseNameFromAPI(api);

            String object = category != null ? category : canonicalApiName;
            if (object == null || object.isEmpty()) {
                continue;
            }

            String verb = inferVerbFromApi(api);
            if (verb == null) {
                verb = "call";
            }

            String name = buildCanonicalName(verb, object, null);

            CandidateName c = new CandidateName();
            c.name = name;
            c.score = 0.75;
            c.reasons.add("Derived from API call: " + api);
            if (category != null) {
                c.reasons.add("Category inferred: " + category);
            }
            result.add(c);
        }

        return result;
    }

    private static List<CandidateName> buildRoleBasedCandidates(SemanticInfo info) {
        List<CandidateName> result = new ArrayList<>();

        if (info.isLikelyDispatcher) {
            CandidateName c = new CandidateName();
            String object = inferObject(info);
            if (object == null || object.equals("unknown")) {
                object = "event";
            }
            c.name = "dispatch_" + object;
            c.score = 0.78;
            c.reasons.add("Control-flow and call graph indicate dispatcher (switch + many callees)");
            result.add(c);
        }

        if (info.isLikelyInitializer) {
            CandidateName c = new CandidateName();
            String object = inferObject(info);
            if (object == null || object.equals("unknown")) {
                object = "state";
            }
            c.name = "init_" + object;
            c.score = 0.76;
            c.reasons.add("Call patterns and strings suggest initialization logic");
            result.add(c);
        }

        if (info.isLikelyCleanup) {
            CandidateName c = new CandidateName();
            String object = inferObject(info);
            if (object == null || object.equals("unknown")) {
                object = "state";
            }
            c.name = "cleanup_" + object;
            c.score = 0.76;
            c.reasons.add("Call patterns and strings suggest cleanup/shutdown logic");
            result.add(c);
        }

        if (info.isLeaf && info.callerCount > 0 && info.calleeCount == 0) {
            CandidateName c = new CandidateName();
            String object = inferObject(info);
            if (object == null || object.equals("unknown")) {
                object = "helper";
            }
            c.name = "compute_" + object;
            c.score = 0.65;
            c.reasons.add("Leaf function with callers; likely computation or helper");
            result.add(c);
        }

        return result;
    }

    private static List<CandidateName> deduplicateCandidates(List<CandidateName> candidates) {
        Map<String, CandidateName> byName = new HashMap<>();
        for (CandidateName c : candidates) {
            if (c.name == null || c.name.isEmpty()) {
                continue;
            }
            String key = c.name.toLowerCase();
            CandidateName existing = byName.get(key);
            if (existing == null || existing.score < c.score) {
                byName.put(key, c);
            } else if (existing == c) {
                // same instance, ignore
            } else {
                // merge reasons into the higher-score candidate
                for (String r : c.reasons) {
                    if (!existing.reasons.contains(r)) {
                        existing.reasons.add(r);
                    }
                }
            }
        }
        return new ArrayList<>(byName.values());
    }

    // ------------------------------------------------------------------------
    // Verb/object/qualifier inference
    // ------------------------------------------------------------------------

    private static String inferVerb(SemanticInfo info) {
        // Role-based verbs first
        if (info.isLikelyDispatcher) {
            return "dispatch";
        }
        if (info.isLikelyInitializer) {
            return "init";
        }
        if (info.isLikelyCleanup) {
            return "cleanup";
        }

        // API-driven verbs
        for (String api : info.apiCalls) {
            String v = inferVerbFromApi(api);
            if (v != null) {
                return v;
            }
        }

        // String-driven verbs
        for (String s : info.nearbyStrings) {
            String v = inferVerbFromString(s);
            if (v != null) {
                return v;
            }
        }

        // Generic heuristics
        if (info.hasLoopLikeBranches && info.returnsValue) {
            return "compute";
        }
        if (info.hasLoopLikeBranches && !info.returnsValue) {
            return "process";
        }
        if (info.isLeaf && info.returnsValue) {
            return "compute";
        }

        // No strong signal; default to "handle"
        return "handle";
    }

    private static String inferVerbFromApi(String api) {
        if (api == null) {
            return null;
        }
        String lower = api.toLowerCase();

        if (lower.startsWith("create")) return "create";
        if (lower.startsWith("open")) return "open";
        if (lower.startsWith("close")) return "close";
        if (lower.startsWith("read")) return "read";
        if (lower.startsWith("write")) return "write";
        if (lower.startsWith("get")) return "get";
        if (lower.startsWith("set")) return "set";
        if (lower.contains("encrypt")) return "encode";
        if (lower.contains("decrypt")) return "decode";
        if (lower.contains("connect") || lower.contains("send") || lower.contains("recv")) return "handle";

        if (lower.contains("init")) return "init";
        if (lower.contains("alloc") || lower.contains("malloc")) return "allocate";
        if (lower.contains("free")) return "release";
        if (lower.contains("hash")) return "compute";

        return null;
    }

    private static String inferVerbFromString(String s) {
        if (s == null) {
            return null;
        }
        String lower = s.toLowerCase();

        if (lower.contains("init") || lower.contains("initialize")) return "init";
        if (lower.contains("load")) return "load";
        if (lower.contains("parse")) return "parse";
        if (lower.contains("read")) return "read";
        if (lower.contains("write") || lower.contains("save")) return "write";
        if (lower.contains("validate") || lower.contains("check")) return "validate";
        if (lower.contains("dispatch") || lower.contains("handle")) return "dispatch";
        if (lower.contains("cleanup") || lower.contains("destroy") || lower.contains("shutdown")) return "cleanup";
        if (lower.contains("compute") || lower.contains("calc")) return "compute";

        return null;
    }

    private static String inferObject(SemanticInfo info) {
        // From tags
        if (info.inferredTags.contains("file_operations")) return "file";
        if (info.inferredTags.contains("network")) return "network";
        if (info.inferredTags.contains("http")) return "request";
        if (info.inferredTags.contains("crypto")) return "crypto";
        if (info.inferredTags.contains("registry")) return "registry";
        if (info.inferredTags.contains("authentication")) return "auth";

        // From API categories
        for (String api : info.apiCalls) {
            String category = API_PATTERNS.get(api);
            if (category != null && !category.isEmpty()) {
                return category;
            }
        }

        // From strings
        for (String s : info.nearbyStrings) {
            String extracted = extractNameFromString(s);
            if (extracted != null && !extracted.isEmpty()) {
                return extracted;
            }
        }

        // From return type
        if (info.returnTypeName != null) {
            String rt = info.returnTypeName.toLowerCase();
            if (rt.contains("bool")) return "flag";
            if (rt.contains("string") || rt.contains("char")) return "string";
            if (rt.contains("handle")) return "handle";
            if (rt.contains("socket")) return "socket";
            if (rt.contains("file")) return "file";
        }

        // Param-based
        if (info.parameterCount > 0) {
            return "param";
        }

        return "unknown";
    }

    private static String inferQualifier(SemanticInfo info) {
        List<String> qualifiers = new ArrayList<>();

        // Caller/callee shape
        if (info.callerCount == 0 && info.calleeCount > 0) {
            qualifiers.add("entry");
        } else if (info.callerCount > 5 && info.calleeCount == 0) {
            qualifiers.add("helper");
        }

        // Loops and switches
        if (info.hasLoopLikeBranches) {
            qualifiers.add("loop");
        }
        if (info.hasSwitch) {
            qualifiers.add("switch");
        }

        if (info.isThunk) {
            qualifiers.add("thunk");
        }

        if (qualifiers.isEmpty()) {
            return null;
        }

        // Compress to a single readable qualifier
        return String.join("_", qualifiers);
    }

    private static String buildCanonicalName(String verb, String object, String qualifier) {
        String v = sanitizeIdentifier(verb);
        String o = sanitizeIdentifier(object);
        String q = qualifier != null ? sanitizeIdentifier(qualifier) : null;

        if (q == null || q.isEmpty()) {
            return v + "_" + o;
        }
        return v + "_" + o + "_" + q;
    }

    private static String sanitizeIdentifier(String s) {
        if (s == null) {
            return "";
        }
        String cleaned = s.toLowerCase()
            .replaceAll("[^a-z0-9_]", "_")
            .replaceAll("_+", "_")
            .replaceAll("^_|_$", "");
        if (cleaned.isEmpty()) {
            cleaned = "unnamed";
        }
        return cleaned;
    }

    // ========================================================================
    // Existing helper methods (extended / reused)
    // ========================================================================

    private static List<String> findNearbyStrings(Program program, Function function) {
        List<String> strings = new ArrayList<>();
        AddressSetView body = function.getBody();

        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();

        for (Address addr : body.getAddresses(true)) {
            Instruction instr = listing.getInstructionAt(addr);
            if (instr == null) {
                continue;
            }
            Reference[] refs = refManager.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                if (toAddr == null) {
                    continue;
                }
                Data data = listing.getDataAt(toAddr);
                if (data != null && data.getValue() instanceof String) {
                    String str = (String) data.getValue();
                    if (str.length() > 3 && str.length() < 100) {
                        strings.add(str);
                    }
                }
            }
        }

        return strings;
    }

    private static List<String> findAPICalls(Program program, Function function) {
        List<String> apiCalls = new ArrayList<>();
        AddressSetView body = function.getBody();
        Listing listing = program.getListing();

        for (Address addr : body.getAddresses(true)) {
            Instruction instr = listing.getInstructionAt(addr);
            if (instr != null && instr.getFlowType().isCall()) {
                Reference[] refs = program.getReferenceManager().getReferencesFrom(addr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    if (toAddr == null) {
                        continue;
                    }
                    Symbol symbol = program.getSymbolTable().getPrimarySymbol(toAddr);
                    if (symbol != null && symbol.isExternal()) {
                        String name = symbol.getName();
                        if (name != null && !name.isEmpty()) {
                            apiCalls.add(name);
                        }
                    }
                }
            }
        }

        return apiCalls;
    }

    private static String extractNameFromString(String str) {
        if (str == null || str.isEmpty()) {
            return null;
        }

        String cleaned = str.toLowerCase()
            .replaceAll("^https?://", "")
            .replaceAll("^www\\.", "")
            .replaceAll("\\.[a-z]{2,4}$", "") // file extensions or TLDs
            .replaceAll("[^a-z0-9_]", "_")
            .replaceAll("_+", "_")
            .replaceAll("^_|_$", "");

        if (cleaned.length() > 3 && cleaned.length() < 50) {
            return cleaned;
        }

        return null;
    }

    private static String extractBaseNameFromAPI(String apiName) {
        if (apiName == null || apiName.isEmpty()) {
            return null;
        }

        String name = apiName;

        if (name.startsWith("Create")) {
            name = name.substring(6);
        } else if (name.startsWith("Get")) {
            name = name.substring(3);
        } else if (name.startsWith("Set")) {
            name = name.substring(3);
        } else if (name.startsWith("Open")) {
            name = name.substring(4);
        } else if (name.startsWith("Close")) {
            name = name.substring(5);
        }

        return camelToSnake(name);
    }

    private static String camelToSnake(String camel) {
        if (camel == null || camel.isEmpty()) {
            return "";
        }
        return camel.replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase();
    }

    private static String findFunctionLibrary(Program program, Function function) {
        // NOTE: This is intentionally conservative. Real library resolution
        // would go through ExternalLocation; here we only provide a hook
        // for future enhancement without breaking existing behavior.
        List<String> apiCalls = findAPICalls(program, function);
        if (!apiCalls.isEmpty()) {
            // Placeholder: in many binaries, import names encode library hints
            // like kernel32!CreateFileA etc. If symbols contain such patterns,
            // they can be parsed here without extra Ghidra APIs.
            return null;
        }
        return null;
    }

    private static boolean hasCryptoOperations(Program program, Function function) {
        List<String> apiCalls = findAPICalls(program, function);
        for (String api : apiCalls) {
            String lower = api.toLowerCase();
            if (lower.contains("crypt") || lower.contains("encrypt") || lower.contains("decrypt") ||
                lower.contains("hash") || lower.contains("md5") || lower.contains("sha")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasNetworkOperations(Program program, Function function) {
        List<String> apiCalls = findAPICalls(program, function);
        for (String api : apiCalls) {
            String lower = api.toLowerCase();
            if (lower.contains("internet") || lower.contains("http") || lower.contains("socket") ||
                lower.contains("connect") || lower.contains("send") || lower.contains("recv")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasFileOperations(Program program, Function function) {
        List<String> apiCalls = findAPICalls(program, function);
        for (String api : apiCalls) {
            String lower = api.toLowerCase();
            if (lower.contains("file") || lower.contains("read") || lower.contains("write") ||
                lower.contains("open") || lower.contains("create")) {
                return true;
            }
        }
        return false;
    }

    private static List<String> generateTagReasons(Program program, Function function, String tag) {
        List<String> reasons = new ArrayList<>();

        // Check API calls
        List<String> apiCalls = findAPICalls(program, function);
        for (String api : apiCalls) {
            List<String> tags = API_TAG_PATTERNS.get(api);
            if (tags != null && tags.contains(tag)) {
                reasons.add("Calls " + api + " API");
            }
        }

        // Check string patterns
        List<String> nearbyStrings = findNearbyStrings(program, function);
        for (String str : nearbyStrings) {
            for (Map.Entry<Pattern, List<String>> entry : STRING_TAG_PATTERNS.entrySet()) {
                if (entry.getKey().matcher(str).find() && entry.getValue().contains(tag)) {
                    reasons.add("Contains string pattern: " + str.substring(0, Math.min(50, str.length())));
                    break;
                }
            }
        }

        if (reasons.isEmpty()) {
            reasons.add("Detected from function characteristics");
        }

        return reasons;
    }

    // ========================================================================
    // Misc helpers
    // ========================================================================

    private static double clamp(double v, double lo, double hi) {
        if (v < lo) return lo;
        if (v > hi) return hi;
        return v;
    }

    private static String applyFunctionContextToVariableName(String base, Function function) {
        if (function == null || base == null || base.isEmpty()) {
            return base != null && !base.isEmpty() ? base : "var";
        }

        // Very small contextual tweak: if function name already contains the base,
        // avoid repeating it; otherwise, we might add a short suffix hint.
        String funcNameLower = function.getName().toLowerCase();
        String baseLower = base.toLowerCase();

        if (funcNameLower.contains(baseLower)) {
            return base;
        }

        // If function name looks like verb_object, reuse the object as a suffix
        String[] parts = funcNameLower.split("_");
        if (parts.length >= 2) {
            String object = parts[parts.length - 1];
            if (!object.equals(baseLower)) {
                return baseLower + "_" + object;
            }
        }

        return baseLower;
    }
}
