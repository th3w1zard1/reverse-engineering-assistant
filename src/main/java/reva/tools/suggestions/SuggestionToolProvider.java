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
package reva.tools.suggestions;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;
import reva.util.SmartSuggestionsUtil;

/**
 * Tool provider for smart suggestions.
 * Provides context-aware suggestions for comments, function names, tags, variables, and data types.
 */
public class SuggestionToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public SuggestionToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerSuggestTool();
    }

    private void registerSuggestTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("suggestionType", Map.of(
            "type", "string",
            "description", "Type of suggestion to get: 'comment_type', 'comment_text', 'function_name', 'function_tags', 'variable_name', 'data_type'",
            "enum", List.of("comment_type", "comment_text", "function_name", "function_tags", "variable_name", "data_type")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address or symbol name (required for comment_type, comment_text, data_type)"));
        properties.put("function", SchemaUtil.stringProperty("Function name or address (required for function_name, function_tags, variable_name)"));
        properties.put("dataType", SchemaUtil.stringProperty("Data type string (required for variable_name suggestion)"));
        properties.put("variableAddress", SchemaUtil.stringProperty("Address of variable/data (required for data_type suggestion)"));

        List<String> required = List.of("programPath", "suggestionType");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("suggest")
            .title("Get Smart Suggestions")
            .description("Get context-aware suggestions for comments, function names, tags, variables, and data types based on program analysis.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String suggestionType = getString(request, "suggestionType");

                switch (suggestionType) {
                    case "comment_type":
                        return handleSuggestCommentType(program, request);
                    case "comment_text":
                        return handleSuggestCommentText(program, request);
                    case "function_name":
                        return handleSuggestFunctionName(program, request);
                    case "function_tags":
                        return handleSuggestFunctionTags(program, request);
                    case "variable_name":
                        return handleSuggestVariableName(program, request);
                    case "data_type":
                        return handleSuggestDataType(program, request);
                    default:
                        return createErrorResult("Invalid suggestionType: " + suggestionType);
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in suggest tool", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleSuggestCommentType(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for suggestionType='comment_type'");
        }

        ghidra.program.model.address.Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        Map<String, Object> suggestion = SmartSuggestionsUtil.suggestCommentType(program, address);

        Map<String, Object> result = new HashMap<>();
        result.put("suggestionType", "comment_type");
        result.put("address", AddressUtil.formatAddress(address));
        result.put("suggestion", suggestion);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSuggestCommentText(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for suggestionType='comment_text'");
        }

        ghidra.program.model.address.Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        Map<String, Object> suggestion = SmartSuggestionsUtil.suggestCommentText(program, address);

        Map<String, Object> result = new HashMap<>();
        result.put("suggestionType", "comment_text");
        result.put("address", AddressUtil.formatAddress(address));
        result.put("suggestion", suggestion);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSuggestFunctionName(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String functionStr = getOptionalString(request, "function", null);
        if (functionStr == null) {
            return createErrorResult("function is required for suggestionType='function_name'");
        }

        Function function = resolveFunction(program, functionStr);
        if (function == null) {
            return createErrorResult("Function not found: " + functionStr);
        }

        List<Map<String, Object>> suggestions = SmartSuggestionsUtil.suggestFunctionNames(program, function);

        Map<String, Object> result = new HashMap<>();
        result.put("suggestionType", "function_name");
        result.put("function", function.getName());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("suggestions", suggestions);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSuggestFunctionTags(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String functionStr = getOptionalString(request, "function", null);
        if (functionStr == null) {
            return createErrorResult("function is required for suggestionType='function_tags'");
        }

        Function function = resolveFunction(program, functionStr);
        if (function == null) {
            return createErrorResult("Function not found: " + functionStr);
        }

        List<Map<String, Object>> suggestions = SmartSuggestionsUtil.suggestFunctionTags(program, function);

        Map<String, Object> result = new HashMap<>();
        result.put("suggestionType", "function_tags");
        result.put("function", function.getName());
        result.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        result.put("currentTags", function.getTags().stream().map(FunctionTag::getName).sorted().toList());
        result.put("suggestions", suggestions);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSuggestVariableName(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String functionStr = getOptionalString(request, "function", null);
        if (functionStr == null) {
            return createErrorResult("function is required for suggestionType='variable_name'");
        }

        String dataType = getOptionalString(request, "dataType", null);
        if (dataType == null) {
            return createErrorResult("dataType is required for suggestionType='variable_name'");
        }

        Function function = resolveFunction(program, functionStr);
        if (function == null) {
            return createErrorResult("Function not found: " + functionStr);
        }

        Map<String, Object> suggestion = SmartSuggestionsUtil.suggestVariableName(program, function, dataType);

        Map<String, Object> result = new HashMap<>();
        result.put("suggestionType", "variable_name");
        result.put("function", function.getName());
        result.put("dataType", dataType);
        result.put("suggestion", suggestion);

        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSuggestDataType(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "variableAddress", null);
        }
        if (addressStr == null) {
            return createErrorResult("address or variableAddress is required for suggestionType='data_type'");
        }

        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        Function function = null;
        String functionStr = getOptionalString(request, "function", null);
        if (functionStr != null) {
            function = resolveFunction(program, functionStr);
        }

        Map<String, Object> suggestion = SmartSuggestionsUtil.suggestDataType(program, function, address);

        Map<String, Object> result = new HashMap<>();
        result.put("suggestionType", "data_type");
        result.put("address", AddressUtil.formatAddress(address));
        result.put("suggestion", suggestion);

        return createJsonResult(result);
    }

    /**
     * Resolve function from identifier (address or name)
     */
    private Function resolveFunction(Program program, String identifier) {
        // Try as address or symbol first
        Address address = AddressUtil.resolveAddressOrSymbol(program, identifier);
        if (address != null) {
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function != null) {
                return function;
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
}
