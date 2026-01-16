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
package reva.tools.strings;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SimilarityComparator;
import reva.util.ToolLogCollector;



/**
 * Tool provider for string-related operations.
 */
public class StringToolProvider extends AbstractToolProvider {
    /**
     * Maximum number of referencing functions to return per string.
     * Prevents unbounded iteration for frequently referenced strings.
     */
    private static final int MAX_REFERENCING_FUNCTIONS = 100;

    /**
     * Temporary key for storing Address objects during similarity search processing.
     * Used to avoid string parsing round-trip; removed before JSON serialization.
     */
    private static final String TEMP_ADDRESS_KEY = "_addressObj";

    /**
     * Constructor
     * @param server The MCP server
     */
    public StringToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageStringsTool();
    }

    private void registerManageStringsTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", Map.of(
            "type", "string",
            "description", "Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser."
        ));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Operation mode: 'list', 'regex', 'count', or 'similarity'",
            "enum", List.of("list", "regex", "count", "similarity"),
            "default", "list"
        ));
        properties.put("pattern", Map.of(
            "type", "string",
            "description", "Regular expression pattern to search for when mode='regex'"
        ));
        properties.put("searchString", Map.of(
            "type", "string",
            "description", "String to compare against for similarity when mode='similarity'"
        ));
        properties.put("filter", Map.of(
            "type", "string",
            "description", "Optional filter to match within string content when mode='list'"
        ));
        properties.put("startIndex", Map.of(
            "type", "integer",
            "description", "Starting index for pagination when mode='list' or 'similarity' (0-based)",
            "default", 0
        ));
        properties.put("maxCount", Map.of(
            "type", "integer",
            "description", "Maximum number of strings to return when mode='list' or 'similarity'",
            "default", 100
        ));
        properties.put("offset", Map.of(
            "type", "integer",
            "description", "Alternative pagination offset when mode='list'",
            "default", 0
        ));
        properties.put("limit", Map.of(
            "type", "integer",
            "description", "Alternative pagination limit when mode='list'",
            "default", 2000
        ));
        properties.put("maxResults", Map.of(
            "type", "integer",
            "description", "Maximum number of results to return when mode='regex'",
            "default", 100
        ));
        properties.put("includeReferencingFunctions", Map.of(
            "type", "boolean",
            "description", "Include list of functions that reference each string when mode='list' or 'similarity'",
            "default", false
        ));

        List<String> required = new ArrayList<>();

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-strings")
            .title("Manage Strings")
            .description("List, search, count, or find similar strings in the program.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String mode = getOptionalString(request, "mode", "list");

                switch (mode) {
                    case "count":
                        return handleStringsCount(program);
                    case "list":
                        return handleStringsList(program, request);
                    case "regex":
                        return handleStringsRegex(program, request);
                    case "similarity":
                        return handleStringsSimilarity(program, request);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: list, regex, count, similarity");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in manage-strings", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleStringsCount(Program program) {
        int count = 0;
        DataIterator dataIterator = program.getListing().getDefinedData(true);
        for (Data data : dataIterator) {
            if (data.getValue() instanceof String) {
                count++;
            }
        }
        Map<String, Object> result = new HashMap<>();
        result.put("count", count);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleStringsList(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int startIndex = getOptionalInt(request, "startIndex",
            getOptionalInt(request, "offset", 0));
        int maxCount = getOptionalInt(request, "maxCount",
            getOptionalInt(request, "limit", 2000));
        boolean includeReferencingFunctions = getOptionalBoolean(request, "includeReferencingFunctions", false);
        String filter = getOptionalString(request, "filter", null);

        ToolLogCollector logCollector = new ToolLogCollector();
        logCollector.start();

        try {
            List<Map<String, Object>> stringData = new ArrayList<>();
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            int currentIndex = 0;
            int iterationCount = 0;
            final int MAX_ITERATIONS = 1000000;

            for (Data data : dataIterator) {
                iterationCount++;
                if (iterationCount > MAX_ITERATIONS) {
                    String logMsg = String.format(
                        "String iteration limit reached (%d iterations) for program %s. " +
                        "Only %d strings found before limit.",
                        MAX_ITERATIONS, program.getName(), stringData.size()
                    );
                    Msg.warn(this, logMsg);
                    logCollector.addLog("WARN", logMsg);
                    break;
                }

                if (!(data.getValue() instanceof String)) {
                    continue;
                }

                if (filter != null && !filter.isEmpty()) {
                    String stringValue = (String) data.getValue();
                    if (!stringValue.contains(filter)) {
                        continue;
                    }
                }

                if (currentIndex++ < startIndex) {
                    continue;
                }

                if (stringData.size() >= maxCount) {
                    break;
                }

                Map<String, Object> stringInfo = getStringInfo(data, program, includeReferencingFunctions);
                if (stringInfo != null) {
                    stringData.add(stringInfo);
                }
            }

            Map<String, Object> paginationInfo = new HashMap<>();
        paginationInfo.put("startIndex", startIndex);
        paginationInfo.put("requestedCount", maxCount);
        paginationInfo.put("actualCount", stringData.size());
        paginationInfo.put("nextStartIndex", startIndex + stringData.size());
            if (logCollector.hasLogs()) {
                ToolLogCollector.addLogsToResult(paginationInfo, logCollector);
            }
            logCollector.stop();

            List<Object> resultData = new ArrayList<>();
            resultData.add(paginationInfo);
            resultData.addAll(stringData);
            return createJsonResult(resultData);
        } catch (Exception e) {
            logCollector.stop();
            throw e;
        }
    }

    private McpSchema.CallToolResult handleStringsRegex(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String patternStr = getOptionalString(request, "pattern", null);
        if (patternStr == null) {
            patternStr = getOptionalString(request, "pattern", null);
        }
        if (patternStr == null) {
            return createErrorResult("pattern is required when mode='regex'");
        }
        int maxResults = getOptionalInt(request, "maxResults",
            getOptionalInt(request, "maxResults", 100));
        int startIndex = getOptionalInt(request, "startIndex",
            getOptionalInt(request, "startIndex", 0));
        boolean includeReferencingFunctions = getOptionalBoolean(request, "includeReferencingFunctions",
            getOptionalBoolean(request, "includeReferencingFunctions", false));

        if (patternStr.trim().isEmpty()) {
            return createErrorResult("Pattern cannot be empty when mode='regex'");
        }

        Pattern pattern;
        try {
            pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            return createErrorResult("Invalid regex pattern: " + e.getMessage());
        }

        List<Map<String, Object>> matchingStrings = new ArrayList<>();
        DataIterator dataIterator = program.getListing().getDefinedData(true);
        int matchesFound = 0;
        boolean searchComplete = true;

        for (Data data : dataIterator) {
            if (!(data.getValue() instanceof String)) {
                continue;
            }

            String stringValue = (String) data.getValue();
            if (pattern.matcher(stringValue).find()) {
                if (matchesFound++ < startIndex) {
                    continue;
                }

                if (matchingStrings.size() >= maxResults) {
                    searchComplete = false;
                    break;
                }

                Map<String, Object> stringInfo = getStringInfo(data, program, includeReferencingFunctions);
                if (stringInfo != null) {
                    matchingStrings.add(stringInfo);
                }
            }
        }

        Map<String, Object> searchMetadata = new HashMap<>();
        searchMetadata.put("regexPattern", patternStr);
        searchMetadata.put("searchComplete", searchComplete);
        searchMetadata.put("startIndex", startIndex);
        searchMetadata.put("requestedCount", maxResults);
        searchMetadata.put("actualCount", matchingStrings.size());
        searchMetadata.put("nextStartIndex", startIndex + matchingStrings.size());

        List<Object> resultData = new ArrayList<>();
        resultData.add(searchMetadata);
        resultData.addAll(matchingStrings);
        return createJsonResult(resultData);
    }

    private McpSchema.CallToolResult handleStringsSimilarity(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String searchString = getOptionalString(request, "searchString", null);
        if (searchString == null) {
            return createErrorResult("searchString is required when mode='similarity'");
        }
        int startIndex = getOptionalInt(request, "startIndex", 0);
        int maxCount = getOptionalInt(request, "maxCount", 100);
        boolean includeReferencingFunctions = getOptionalBoolean(request, "includeReferencingFunctions", false);

        if (searchString.trim().isEmpty()) {
            return createErrorResult("searchString cannot be empty when mode='similarity'");
        }

        DataIterator dataIterator = program.getListing().getDefinedData(true);
        List<Map<String, Object>> allStringData = new ArrayList<>();

        for (Data data : dataIterator) {
            if (data.getValue() instanceof String) {
                Map<String, Object> stringInfo = getStringInfo(data);
                if (stringInfo != null) {
                    stringInfo.put(TEMP_ADDRESS_KEY, data.getAddress());
                    allStringData.add(stringInfo);
                }
            }
        }

        Collections.sort(allStringData, new SimilarityComparator<Map<String, Object>>(searchString, new SimilarityComparator.StringExtractor<Map<String, Object>>() {
            @Override
            public String extract(Map<String, Object> item) {
                return (String) item.get("content");
            }
        }));

        int startIdx = Math.min(startIndex, allStringData.size());
        int endIdx = Math.min(startIndex + maxCount, allStringData.size());
        List<Map<String, Object>> paginatedStringData = new ArrayList<>(allStringData.subList(startIdx, endIdx));
        boolean searchComplete = endIdx >= allStringData.size();

        for (Map<String, Object> stringInfo : paginatedStringData) {
            Address address = (Address) stringInfo.remove(TEMP_ADDRESS_KEY);
            if (includeReferencingFunctions && address != null) {
                List<Map<String, String>> referencingFunctions = getReferencingFunctions(program, address);
                stringInfo.put("referencingFunctions", referencingFunctions);
                stringInfo.put("referenceCount", referencingFunctions.size());
            }
        }

        Map<String, Object> paginationInfo = new HashMap<>();
        paginationInfo.put("searchComplete", searchComplete);
        paginationInfo.put("startIndex", startIndex);
        paginationInfo.put("requestedCount", maxCount);
        paginationInfo.put("actualCount", paginatedStringData.size());
        paginationInfo.put("nextStartIndex", startIndex + paginatedStringData.size());

        List<Object> resultData = new ArrayList<>();
        resultData.add(paginationInfo);
        resultData.addAll(paginatedStringData);
        return createJsonResult(resultData);
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Extract string information from a Ghidra Data object
     * @param data The data object containing a string
     * @return Map of string properties or null if not a string
     */
    private Map<String, Object> getStringInfo(Data data) {
        return getStringInfo(data, null, false);
    }

    /**
     * Extract string information from a Ghidra Data object with optional referencing functions
     * @param data The data object containing a string
     * @param program The program (required if includeReferencingFunctions is true)
     * @param includeReferencingFunctions Whether to include list of functions that reference this string
     * @return Map of string properties or null if not a string
     */
    private Map<String, Object> getStringInfo(Data data, Program program, boolean includeReferencingFunctions) {
        if (!(data.getValue() instanceof String)) {
            return null;
        }

        String stringValue = (String) data.getValue();

        Map<String, Object> stringInfo = new HashMap<>();
        stringInfo.put("address", AddressUtil.formatAddress(data.getAddress()));
        stringInfo.put("content", stringValue);
        stringInfo.put("length", stringValue.length());

        // Get the raw bytes
        try {
            byte[] bytes = data.getBytes();
            if (bytes != null) {
                // Convert bytes to hex string
                StringBuilder hexString = new StringBuilder();
                for (byte b : bytes) {
                    hexString.append(String.format("%02x", b & 0xff));
                }
                stringInfo.put("hexBytes", hexString.toString());
                stringInfo.put("byteLength", bytes.length);
            }
        } catch (MemoryAccessException e) {
            stringInfo.put("bytesError", "Memory access error: " + e.getMessage());
        }

        // Add the data type and representation
        stringInfo.put("dataType", data.getDataType().getName());
        stringInfo.put("representation", data.getDefaultValueRepresentation());

        // Add referencing functions if requested
        if (includeReferencingFunctions && program != null) {
            List<Map<String, String>> referencingFunctions = getReferencingFunctions(program, data.getAddress());
            stringInfo.put("referencingFunctions", referencingFunctions);
            stringInfo.put("referenceCount", referencingFunctions.size());
        }

        return stringInfo;
    }

    /**
     * Get list of functions that reference a given address
     * @param program The program
     * @param address The address to find references to
     * @return List of function info maps (name, address), limited to MAX_REFERENCING_FUNCTIONS
     */
    private List<Map<String, String>> getReferencingFunctions(Program program, Address address) {
        List<Map<String, String>> functions = new ArrayList<>();
        Set<String> seenFunctions = new HashSet<>();

        ReferenceManager refManager = program.getReferenceManager();
        FunctionManager funcManager = program.getFunctionManager();
        ReferenceIterator refIter = refManager.getReferencesTo(address);

        while (refIter.hasNext() && functions.size() < MAX_REFERENCING_FUNCTIONS) {
            Reference ref = refIter.next();
            Function func = funcManager.getFunctionContaining(ref.getFromAddress());

            if (func != null) {
                String funcKey = func.getEntryPoint().toString();
                if (!seenFunctions.contains(funcKey)) {
                    seenFunctions.add(funcKey);
                    Map<String, String> funcInfo = new HashMap<>();
                    funcInfo.put("name", func.getName());
                    funcInfo.put("address", AddressUtil.formatAddress(func.getEntryPoint()));
                    functions.add(funcInfo);
                }
            }
        }

        return functions;
    }
}
