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
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

/**
 * Utility class for providing smart suggestions based on program context.
 * Provides heuristics-based suggestions for comment types, function names,
 * variable names, etc.
 */
public class SmartSuggestionsUtil {

    // Common API patterns for function name suggestions
    private static final Map<String, String> API_PATTERNS = Map.of(
            "CreateFile", "file_operations",
            "ReadFile", "file_operations",
            "WriteFile", "file_operations",
            "CloseHandle", "file_operations",
            "RegOpenKey", "registry_operations",
            "RegQueryValue", "registry_operations",
            "InternetOpen", "network_operations",
            "HttpSendRequest", "network_operations",
            "CryptAcquireContext", "crypto_operations",
            "CryptEncrypt", "crypto_operations",
            "CryptDecrypt", "crypto_operations",
            "malloc", "memory_operations",
            "free", "memory_operations",
            "strcpy", "string_operations",
            "strcmp", "string_operations"
    );

    // Data type to variable name suggestions
    private static final Map<String, String> TYPE_NAME_PATTERNS = Map.of(
            "char*", "buffer",
            "char[]", "buffer",
            "int", "value",
            "uint", "value",
            "long", "value",
            "void*", "ptr",
            "int*", "array",
            "struct", "item",
            "FILE*", "file"
    );

    // Library to tag mappings
    private static final Map<String, List<String>> LIBRARY_TAG_PATTERNS = Map.of(
            "kernel32", List.of("windows_api", "system"),
            "user32", List.of("windows_api", "ui"),
            "advapi32", List.of("windows_api", "registry", "security"),
            "ws2_32", List.of("network", "windows_api"),
            "wininet", List.of("network", "http"),
            "crypt32", List.of("crypto", "security"),
            "ntdll", List.of("windows_api", "system", "low_level"),
            "msvcrt", List.of("c_runtime", "standard_library"),
            "libc", List.of("c_runtime", "standard_library"),
            "libssl", List.of("crypto", "network"),
            "libcrypto", List.of("crypto", "security")
    );

    // String pattern to tag mappings
    private static final Map<Pattern, List<String>> STRING_TAG_PATTERNS = Map.of(
            Pattern.compile("https?://", Pattern.CASE_INSENSITIVE), List.of("network", "http"),
            Pattern.compile("ftp://", Pattern.CASE_INSENSITIVE), List.of("network", "ftp"),
            Pattern.compile("\\.[a-z]{2,4}$", Pattern.CASE_INSENSITIVE), List.of("file_operations"),
            Pattern.compile("password|secret|key|token", Pattern.CASE_INSENSITIVE), List.of("security", "authentication"),
            Pattern.compile("encrypt|decrypt|cipher", Pattern.CASE_INSENSITIVE), List.of("crypto"),
            Pattern.compile("md5|sha1|sha256|aes|des", Pattern.CASE_INSENSITIVE), List.of("crypto", "hashing"),
            Pattern.compile("registry|reg_", Pattern.CASE_INSENSITIVE), List.of("registry", "windows_api"),
            Pattern.compile("createfile|readfile|writefile", Pattern.CASE_INSENSITIVE), List.of("file_operations")
    );

    // API to tag mappings (more comprehensive)
    private static final Map<String, List<String>> API_TAG_PATTERNS = Map.of(
            "CreateFile", List.of("file_operations", "io"),
            "ReadFile", List.of("file_operations", "io"),
            "WriteFile", List.of("file_operations", "io"),
            "CryptAcquireContext", List.of("crypto", "security"),
            "CryptEncrypt", List.of("crypto", "security"),
            "CryptDecrypt", List.of("crypto", "security"),
            "InternetOpen", List.of("network", "http"),
            "HttpSendRequest", List.of("network", "http"),
            "RegOpenKey", List.of("registry", "windows_api"),
            "RegQueryValue", List.of("registry", "windows_api"),
            "malloc", List.of("memory_operations"),
            "free", List.of("memory_operations"),
            "strcpy", List.of("string_operations"),
            "strcmp", List.of("string_operations")
    );

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
            suggestion.put("comment_type", "eol");
            suggestion.put("confidence", 0.5);
            suggestion.put("reason", "Default suggestion");
            return suggestion;
        }

        Listing listing = program.getListing();
        FunctionManager funcManager = program.getFunctionManager();

        // Check if address is a function entry point
        Function function = funcManager.getFunctionContaining(address);
        if (function != null && function.getEntryPoint().equals(address)) {
            suggestion.put("comment_type", "plate");
            suggestion.put("confidence", 0.9);
            suggestion.put("reason", "Address is a function entry point - plate comments are typically used for function headers");
            return suggestion;
        }

        // Check if address has data (not code)
        Data data = listing.getDataAt(address);
        if (data != null) {
            suggestion.put("comment_type", "pre");
            suggestion.put("confidence", 0.8);
            suggestion.put("reason", "Address contains data - pre comments are typically used for data structures");
            return suggestion;
        }

        // Check if address is an instruction
        Instruction instruction = listing.getInstructionAt(address);
        if (instruction != null) {
            // Check if it's a call instruction
            if (instruction.getFlowType().isCall()) {
                suggestion.put("comment_type", "eol");
                suggestion.put("confidence", 0.85);
                suggestion.put("reason", "Address is a call instruction - eol comments are typically used for inline annotations");
            } else {
                suggestion.put("comment_type", "eol");
                suggestion.put("confidence", 0.7);
                suggestion.put("reason", "Address is an instruction - eol comments are the most common for code annotations");
            }
            return suggestion;
        }

        // Default to eol
        suggestion.put("comment_type", "eol");
        suggestion.put("confidence", 0.6);
        suggestion.put("reason", "Default suggestion for code addresses");
        return suggestion;
    }

    /**
     * Suggest function names based on context (strings, API calls, patterns)
     *
     * @param program The program
     * @param function The function to analyze
     * @return List of suggested names with confidence scores and reasons
     */
    public static List<Map<String, Object>> suggestFunctionNames(Program program, Function function) {
        List<Map<String, Object>> suggestions = new ArrayList<>();

        if (program == null || function == null) {
            return suggestions;
        }

        // Strategy 1: Check for string references nearby
        List<String> nearbyStrings = findNearbyStrings(program, function);
        for (String str : nearbyStrings) {
            String suggestion = extractNameFromString(str);
            if (suggestion != null && !suggestion.isEmpty()) {
                Map<String, Object> sug = new HashMap<>();
                sug.put("name", suggestion);
                sug.put("confidence", 0.75);
                sug.put("reasons", List.of("Found nearby string: " + str));
                suggestions.add(sug);
            }
        }

        // Strategy 2: Check for API calls
        List<String> apiCalls = findAPICalls(program, function);
        for (String api : apiCalls) {
            String category = API_PATTERNS.get(api);
            if (category != null) {
                Map<String, Object> sug = new HashMap<>();
                sug.put("name", category + "_handler");
                sug.put("confidence", 0.8);
                sug.put("reasons", List.of("Calls " + api + " API"));
                suggestions.add(sug);
            } else {
                // Extract base name from API
                String baseName = extractBaseNameFromAPI(api);
                if (baseName != null) {
                    Map<String, Object> sug = new HashMap<>();
                    sug.put("name", baseName);
                    sug.put("confidence", 0.7);
                    sug.put("reasons", List.of("Calls " + api + " API"));
                    suggestions.add(sug);
                }
            }
        }

        // Strategy 3: Check parameter count and types
        int paramCount = function.getParameterCount();
        if (paramCount > 0) {
            String paramBasedName = suggestNameFromParameters(function);
            if (paramBasedName != null) {
                Map<String, Object> sug = new HashMap<>();
                sug.put("name", paramBasedName);
                sug.put("confidence", 0.65);
                sug.put("reasons", List.of("Based on parameter count: " + paramCount));
                suggestions.add(sug);
            }
        }

        // Strategy 4: Check call patterns
        int callerCount = function.getCallingFunctions(null).length;
        int calleeCount = function.getCalledFunctions(null).length;
        if (callerCount == 0 && calleeCount > 0) {
            Map<String, Object> sug = new HashMap<>();
            sug.put("name", "helper_function");
            sug.put("confidence", 0.6);
            sug.put("reasons", List.of("No callers, only called functions - likely a helper"));
            suggestions.add(sug);
        }

        // Remove duplicates and sort by confidence
        suggestions = deduplicateSuggestions(suggestions);
        suggestions.sort((a, b) -> {
            double confA = (Double) a.get("confidence");
            double confB = (Double) b.get("confidence");
            return Double.compare(confB, confA);
        });

        return suggestions;
    }

    /**
     * Suggest variable names based on data type and usage context
     *
     * @param program The program
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

        // Check type patterns
        for (Map.Entry<String, String> entry : TYPE_NAME_PATTERNS.entrySet()) {
            if (normalizedType.contains(entry.getKey().toLowerCase())) {
                suggestion.put("name", entry.getValue());
                suggestion.put("confidence", 0.7);
                suggestion.put("reason", "Based on data type pattern: " + entry.getKey());
                return suggestion;
            }
        }

        // Check for pointer types
        if (normalizedType.contains("*") || normalizedType.contains("ptr")) {
            suggestion.put("name", "ptr");
            suggestion.put("confidence", 0.65);
            suggestion.put("reason", "Pointer type detected");
            return suggestion;
        }

        // Check for array types
        if (normalizedType.contains("[") || normalizedType.contains("array")) {
            suggestion.put("name", "array");
            suggestion.put("confidence", 0.65);
            suggestion.put("reason", "Array type detected");
            return suggestion;
        }

        // Default suggestion
        suggestion.put("name", "value");
        suggestion.put("confidence", 0.5);
        suggestion.put("reason", "Generic suggestion for type: " + dataType);
        return suggestion;
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================
    private static List<String> findNearbyStrings(Program program, Function function) {
        List<String> strings = new ArrayList<>();
        AddressSet body = function.getBody();

        // Search for string references within function body
        ReferenceManager refManager = program.getReferenceManager();
        for (Address addr : body) {
            Reference[] refs = refManager.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Data data = program.getListing().getDataAt(toAddr);
                if (data != null && data.getValue() instanceof String) {
                    String str = (String) data.getValue();
                    if (str.length() > 3 && str.length() < 100) { // Reasonable string length
                        strings.add(str);
                    }
                }
            }
        }

        return strings;
    }

    private static List<String> findAPICalls(Program program, Function function) {
        List<String> apiCalls = new ArrayList<>();
        AddressSet body = function.getBody();
        Listing listing = program.getListing();

        for (Address addr : body) {
            Instruction instr = listing.getInstructionAt(addr);
            if (instr != null && instr.getFlowType().isCall()) {
                Reference[] refs = program.getReferenceManager().getReferencesFrom(addr);
                for (Reference ref : refs) {
                    Symbol symbol = program.getSymbolTable().getPrimarySymbol(ref.getToAddress());
                    if (symbol != null) {
                        String name = symbol.getName();
                        // Check if it's an import/external function
                        if (symbol.isExternal()) {
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

        // Try to extract meaningful name from string
        // Remove common prefixes/suffixes
        String cleaned = str.toLowerCase()
                .replaceAll("^https?://", "")
                .replaceAll("^www\\.", "")
                .replaceAll("\\.[a-z]{2,4}$", "") // Remove file extensions
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

        // Remove common prefixes
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

        // Convert to snake_case
        return camelToSnake(name);
    }

    private static String camelToSnake(String camel) {
        if (camel == null || camel.isEmpty()) {
            return null;
        }
        return camel.replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase();
    }

    private static String suggestNameFromParameters(Function function) {
        int paramCount = function.getParameterCount();

        if (paramCount == 1) {
            return "process_single";
        } else if (paramCount == 2) {
            return "process_pair";
        } else if (paramCount == 3) {
            return "process_triple";
        } else if (paramCount > 3) {
            return "process_multiple";
        }

        return null;
    }

    private static List<Map<String, Object>> deduplicateSuggestions(List<Map<String, Object>> suggestions) {
        List<Map<String, Object>> deduped = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();

        for (Map<String, Object> sug : suggestions) {
            String name = (String) sug.get("name");
            if (name != null && !seen.contains(name.toLowerCase())) {
                seen.add(name.toLowerCase());
                deduped.add(sug);
            }
        }

        return deduped;
    }

    /**
     * Suggest function tags based on function characteristics, strings, and API calls
     * @param program The program
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
        // Crypto operations detection
        if (hasCryptoOperations(program, function)) {
            tagScores.put("crypto", tagScores.getOrDefault("crypto", 0.0) + 0.85);
        }

        // Network operations detection
        if (hasNetworkOperations(program, function)) {
            tagScores.put("network", tagScores.getOrDefault("network", 0.0) + 0.85);
        }

        // File operations detection
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

    /**
     * Suggest recommended comment text based on address context
     * @param program The program
     * @param address The address to analyze
     * @return Suggested comment text with confidence
     */
    public static Map<String, Object> suggestCommentText(Program program, Address address) {
        Map<String, Object> suggestion = new HashMap<>();

        if (address == null || program == null) {
            suggestion.put("comment", "");
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
                if (paramCount > 1) comment.append("s");
                comment.append(")");
            }

            suggestion.put("comment", comment.toString());
            suggestion.put("confidence", 0.8);
            suggestion.put("reason", "Function entry point - suggests function header comment");
            return suggestion;
        }

        // Check for data structures
        Data data = program.getListing().getDataAt(address);
        if (data != null) {
            String dataType = data.getDataType().getName();
            suggestion.put("comment", "Data: " + dataType);
            suggestion.put("confidence", 0.7);
            suggestion.put("reason", "Data address - suggests data structure comment");
            return suggestion;
        }

        // Default: no specific suggestion
        suggestion.put("comment", "");
        suggestion.put("confidence", 0.3);
        suggestion.put("reason", "No specific context for comment suggestion");
        return suggestion;
    }

    /**
     * Suggest data type based on usage patterns and context
     * @param program The program
     * @param function The function containing the variable
     * @param address The address of the data/variable
     * @return Suggested data type with confidence
     */
    public static Map<String, Object> suggestDataType(Program program, Function function, Address address) {
        Map<String, Object> suggestion = new HashMap<>();

        if (program == null || address == null) {
            suggestion.put("data_type", "void*");
            suggestion.put("confidence", 0.3);
            return suggestion;
        }

        // Check existing data type
        Data data = program.getListing().getDataAt(address);
        if (data != null) {
            String currentType = data.getDataType().getName();
            suggestion.put("data_type", currentType);
            suggestion.put("confidence", 0.9);
            suggestion.put("reason", "Data type already defined at address");
            return suggestion;
        }

        // Check for string references
        List<String> nearbyStrings = findNearbyStrings(program, function);
        if (!nearbyStrings.isEmpty()) {
            suggestion.put("data_type", "char*");
            suggestion.put("confidence", 0.75);
            suggestion.put("reason", "Nearby string references suggest char* type");
            return suggestion;
        }

        // Default suggestion
        suggestion.put("data_type", "int");
        suggestion.put("confidence", 0.5);
        suggestion.put("reason", "Default suggestion - analyze usage for better type");
        return suggestion;
    }

    // ========================================================================
    // Additional Helper Methods
    // ========================================================================

    private static String findFunctionLibrary(Program program, Function function) {
        // Check if function calls external functions and get their library
        List<String> apiCalls = findAPICalls(program, function);
        if (!apiCalls.isEmpty()) {
            // Try to find the library from the first external call
            ReferenceManager refManager = program.getReferenceManager();
            AddressSet body = function.getBody();
            for (Address addr : body) {
                Instruction instr = program.getListing().getInstructionAt(addr);
                if (instr != null && instr.getFlowType().isCall()) {
                    Reference[] refs = refManager.getReferencesFrom(addr);
                    for (Reference ref : refs) {
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(ref.getToAddress());
                        if (symbol != null && symbol.isExternal()) {
                            // Try to extract library from external symbol path
                            // This is a simplified check - in reality, we'd need to check ExternalLocation
                            // For now, we can infer from API name patterns
                            return null; // Placeholder - would need more Ghidra API access
                        }
                    }
                }
            }
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
}
