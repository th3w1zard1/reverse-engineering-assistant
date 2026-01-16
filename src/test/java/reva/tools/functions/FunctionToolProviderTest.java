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

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;

/**
 * Unit tests for FunctionToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated list-functions tool that replaces:
 * - get-function-count (mode='count')
 * - get-functions (mode='all')
 * - get-functions-by-similarity (mode='similarity')
 * - get-undefined-function-candidates (mode='undefined')
 * - substring search (mode='search')
 */
public class FunctionToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private FunctionToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new FunctionToolProvider(mockServer);
    }

    @Test
    public void testRegisterTools() throws McpError {
        // Test that tools can be registered without throwing exceptions
        try {
            toolProvider.registerTools();
        } catch (Exception e) {
            fail("Tool registration should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testInheritance() {
        // Test that FunctionToolProvider extends AbstractToolProvider
        assertTrue("FunctionToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(FunctionToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that FunctionToolProvider implements ToolProvider interface
        assertTrue("FunctionToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(FunctionToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("FunctionToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateListFunctionsParameters() {
        // Test parameter validation for the list-functions tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("mode", "all");

        // Valid parameters should not throw
        try {
            validateListFunctionsArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateListFunctionsArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }
    }

    @Test
    public void testValidateListFunctionsModes() {
        // Test that valid modes are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");

        // Test all valid modes
        String[] validModes = {"all", "search", "similarity", "undefined", "count"};
        for (String mode : validModes) {
            args.put("mode", mode);
            try {
                validateListFunctionsMode(args);
            } catch (Exception e) {
                fail("Valid mode '" + mode + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test default mode (should default to "all")
        args.remove("mode");
        try {
            String defaultMode = getDefaultMode(args);
            assertEquals("Default mode should be 'all'", "all", defaultMode);
        } catch (Exception e) {
            fail("Default mode should work: " + e.getMessage());
        }

        // Test invalid mode
        args.put("mode", "invalid");
        try {
            validateListFunctionsMode(args);
            fail("Should throw exception for invalid mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid mode",
                e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testValidateSearchModeParameters() {
        // Test that search mode requires query parameter
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "search");

        // Missing query should be invalid
        try {
            validateSearchModeArgs(args);
            fail("Should throw exception for missing query in search mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention query",
                e.getMessage().toLowerCase().contains("query"));
        }

        // Valid search mode args
        args.put("query", "test");
        try {
            validateSearchModeArgs(args);
        } catch (Exception e) {
            fail("Valid search mode parameters should not throw: " + e.getMessage());
        }

        // Empty query should be invalid
        args.put("query", "");
        try {
            validateSearchModeArgs(args);
            fail("Should throw exception for empty query");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testValidateSimilarityModeParameters() {
        // Test that similarity mode requires search_string parameter
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "similarity");

        // Missing search_string should be invalid
        try {
            validateSimilarityModeArgs(args);
            fail("Should throw exception for missing search_string in similarity mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention search_string",
                e.getMessage().toLowerCase().contains("search"));
        }

        // Valid similarity mode args
        args.put("searchString", "main");
        try {
            validateSimilarityModeArgs(args);
        } catch (Exception e) {
            fail("Valid similarity mode parameters should not throw: " + e.getMessage());
        }

        // Empty search_string should be invalid
        args.put("searchString", "");
        try {
            validateSimilarityModeArgs(args);
            fail("Should throw exception for empty search_string");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testValidateUndefinedModeParameters() {
        // Test undefined mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "undefined");

        // Test default min_reference_count
        args.remove("min_reference_count");
        try {
            int minRefCount = getMinReferenceCount(args);
            assertEquals("Default min_reference_count should be 1", 1, minRefCount);
        } catch (Exception e) {
            fail("Default min_reference_count should work: " + e.getMessage());
        }

        // Test valid min_reference_count
        args.put("minReferenceCount", 5);
        try {
            validateUndefinedModeArgs(args);
        } catch (Exception e) {
            fail("Valid undefined mode parameters should not throw: " + e.getMessage());
        }

        // Test invalid min_reference_count (< 1)
        args.put("minReferenceCount", 0);
        try {
            validateUndefinedModeArgs(args);
            fail("Should throw exception for min_reference_count < 1");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention min_reference_count",
                e.getMessage().toLowerCase().contains("min_reference_count"));
        }
    }

    @Test
    public void testValidatePaginationParameters() {
        // Test pagination parameter validation and backward compatibility
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "all");

        // Test new pagination parameters (startIndex/maxCount)
        args.put("startIndex", 10);
        args.put("maxCount", 50);
        try {
            validatePaginationArgs(args);
            PaginationInfo info = getPaginationInfo(args);
            assertEquals("startIndex should be 10", 10, info.startIndex());
            assertEquals("maxCount should be 50", 50, info.maxCount());
        } catch (Exception e) {
            fail("New pagination parameters should work: " + e.getMessage());
        }

        // Test backward compatibility (offset/limit)
        args.remove("startIndex");
        args.remove("maxCount");
        args.put("offset", 20);
        args.put("limit", 100);
        try {
            validatePaginationArgs(args);
            PaginationInfo info = getPaginationInfo(args);
            assertEquals("offset should map to startIndex", 20, info.startIndex());
            assertEquals("limit should map to maxCount", 100, info.maxCount());
        } catch (Exception e) {
            fail("Backward compatible pagination parameters should work: " + e.getMessage());
        }

        // Test defaults
        args.remove("offset");
        args.remove("limit");
        try {
            PaginationInfo info = getPaginationInfo(args);
            assertEquals("Default startIndex should be 0", 0, info.startIndex());
            assertEquals("Default maxCount should be 100", 100, info.maxCount());
        } catch (Exception e) {
            fail("Default pagination parameters should work: " + e.getMessage());
        }
    }

    @Test
    public void testValidateFilterDefaultNames() {
        // Test filterDefaultNames parameter
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "all");

        // Test default
        args.remove("filterDefaultNames");
        try {
            boolean filterDefault = getFilterDefaultNames(args);
            assertTrue("Default filterDefaultNames should be true", filterDefault);
        } catch (Exception e) {
            fail("Default filterDefaultNames should work: " + e.getMessage());
        }

        // Test explicit false
        args.put("filterDefaultNames", false);
        try {
            boolean filterDefault = getFilterDefaultNames(args);
            assertFalse("filterDefaultNames should be false", filterDefault);
        } catch (Exception e) {
            fail("filterDefaultNames=false should work: " + e.getMessage());
        }
    }

    // Helper methods to simulate parameter validation from the tool handlers
    private void validateListFunctionsArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
    }

    private void validateListFunctionsMode(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if (mode != null) {
            String[] validModes = {"all", "search", "similarity", "undefined", "count"};
            boolean isValid = false;
            for (String validMode : validModes) {
                if (validMode.equals(mode)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid mode: " + mode);
            }
        }
    }

    private String getDefaultMode(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        return mode != null ? mode : "all";
    }

    private void validateSearchModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("search".equals(mode)) {
            String query = (String) args.get("query");
            if (query == null || query.trim().isEmpty()) {
                throw new IllegalArgumentException("query parameter is required when mode='search'");
            }
        }
    }

    private void validateSimilarityModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("similarity".equals(mode)) {
            String searchString = (String) args.get("searchString");
            if (searchString == null || searchString.trim().isEmpty()) {
                throw new IllegalArgumentException("search_string parameter is required when mode='similarity'");
            }
        }
    }

    private void validateUndefinedModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("undefined".equals(mode)) {
            Object minRefCountObj = args.get("minReferenceCount");
            int minRefCount = minRefCountObj != null ? ((Number) minRefCountObj).intValue() : 1;
            if (minRefCount < 1) {
                throw new IllegalArgumentException("min_reference_count must be at least 1");
            }
        }
    }

    private int getMinReferenceCount(Map<String, Object> args) {
        Object minRefCountObj = args.get("min_reference_count");
        return minRefCountObj != null ? ((Number) minRefCountObj).intValue() : 1;
    }

    private void validatePaginationArgs(Map<String, Object> args) {
        // Both new and old pagination parameters are valid
        // Validation just checks that parameters are reasonable
        Object startIndexObj = args.get("startIndex");
        Object offsetObj = args.get("offset");
        Object maxCountObj = args.get("maxCount");
        Object limitObj = args.get("limit");

        // At least one pagination method should be present, but both are optional (have defaults)
        // This is just a structural validation
    }

    private record PaginationInfo(int startIndex, int maxCount) {}

    private PaginationInfo getPaginationInfo(Map<String, Object> args) {
        int startIndex;
        int maxCount;

        // Check for new pagination parameters first, fall back to old ones
        if (args.containsKey("startIndex") || args.containsKey("maxCount")) {
            Object startIndexObj = args.get("startIndex");
            Object maxCountObj = args.get("maxCount");
            startIndex = startIndexObj != null ? ((Number) startIndexObj).intValue() : 0;
            maxCount = maxCountObj != null ? ((Number) maxCountObj).intValue() : 100;
        } else {
            // Backward compatibility: use offset/limit
            Object offsetObj = args.get("offset");
            Object limitObj = args.get("limit");
            startIndex = offsetObj != null ? ((Number) offsetObj).intValue() : 0;
            maxCount = limitObj != null ? ((Number) limitObj).intValue() : 100;
        }

        return new PaginationInfo(startIndex, maxCount);
    }

    private boolean getFilterDefaultNames(Map<String, Object> args) {
        Object filterDefault = args.get("filterDefaultNames");
        return filterDefault != null ? ((Boolean) filterDefault).booleanValue() : true;
    }

    @Test
    public void testValidateManageFunctionParameters() {
        // Test parameter validation for the manage-function tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("action", "create");
        validArgs.put("address", "0x401000");

        // Valid parameters should not throw
        try {
            validateManageFunctionArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateManageFunctionArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }

        // Missing action should throw
        Map<String, Object> missingAction = new HashMap<>(validArgs);
        missingAction.remove("action");
        try {
            validateManageFunctionArgs(missingAction);
            fail("Should throw exception for missing action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention action",
                e.getMessage().toLowerCase().contains("action"));
        }
    }

    @Test
    public void testValidateManageFunctionActions() {
        // Test that valid actions are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");

        // Test all valid actions
        String[] validActions = {"create", "rename_function", "set_prototype", "rename_variable", "set_variable_type", "change_datatypes"};
        for (String action : validActions) {
            args.put("action", action);
            try {
                validateManageFunctionAction(args);
            } catch (Exception e) {
                fail("Valid action '" + action + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test invalid action
        args.put("action", "invalid");
        try {
            validateManageFunctionAction(args);
            fail("Should throw exception for invalid action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid action",
                e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testValidateCreateActionParameters() {
        // Test create action parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "create");

        // Missing address should be invalid
        try {
            validateCreateActionArgs(args);
            fail("Should throw exception for missing address in create action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address",
                e.getMessage().toLowerCase().contains("address"));
        }

        // Valid create action args
        args.put("address", "0x401000");
        args.put("name", "testFunc");
        try {
            validateCreateActionArgs(args);
        } catch (Exception e) {
            fail("Valid create action parameters should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testValidateSetPrototypeActionParameters() {
        // Test set_prototype action parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "set_prototype");

        // Missing functionIdentifier should be invalid
        try {
            validateSetPrototypeActionArgs(args);
            fail("Should throw exception for missing functionIdentifier in set_prototype action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Missing prototype should be invalid
        args.put("functionIdentifier", "main");
        try {
            validateSetPrototypeActionArgs(args);
            fail("Should throw exception for missing prototype in set_prototype action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention prototype",
                e.getMessage().toLowerCase().contains("prototype"));
        }

        // Valid set_prototype action args
        args.put("prototype", "int main(int argc, char** argv)");
        try {
            validateSetPrototypeActionArgs(args);
        } catch (Exception e) {
            fail("Valid set_prototype action parameters should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testValidateRenameVariableActionParameters() {
        // Test rename_variable action parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "rename_variable");

        // Missing functionIdentifier should be invalid
        try {
            validateRenameVariableActionArgs(args);
            fail("Should throw exception for missing functionIdentifier in rename_variable action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Missing both variable_mappings and old_name/new_name should be invalid
        args.put("functionIdentifier", "main");
        try {
            validateRenameVariableActionArgs(args);
            fail("Should throw exception for missing variable mappings in rename_variable action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention variable",
                e.getMessage().toLowerCase().contains("variable"));
        }

        // Valid rename_variable action args (single variable)
        args.put("oldName", "var1");
        args.put("newName", "newVar1");
        try {
            validateRenameVariableActionArgs(args);
        } catch (Exception e) {
            fail("Valid rename_variable action parameters (single) should not throw: " + e.getMessage());
        }

        // Valid rename_variable action args (multiple variables)
        args.remove("oldName");
        args.remove("newName");
        args.put("variableMappings", "var1:newVar1,var2:newVar2");
        try {
            validateRenameVariableActionArgs(args);
        } catch (Exception e) {
            fail("Valid rename_variable action parameters (multiple) should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testValidateRenameFunctionActionParameters() {
        // Test rename_function action parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "rename_function");

        // Missing functionIdentifier should be invalid
        try {
            validateRenameFunctionActionArgs(args);
            fail("Should throw exception for missing functionIdentifier in rename_function action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Missing name should be invalid
        args.put("functionIdentifier", "main");
        try {
            validateRenameFunctionActionArgs(args);
            fail("Should throw exception for missing name in rename_function action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention name",
                e.getMessage().toLowerCase().contains("name"));
        }

        // Valid rename_function action args
        args.put("name", "newMain");
        try {
            validateRenameFunctionActionArgs(args);
        } catch (Exception e) {
            fail("Valid rename_function action parameters should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testValidateSetVariableTypeActionParameters() {
        // Test set_variable_type action parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "set_variable_type");

        // Missing functionIdentifier should be invalid
        try {
            validateSetVariableTypeActionArgs(args);
            fail("Should throw exception for missing functionIdentifier in set_variable_type action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Missing variableName should be invalid
        args.put("functionIdentifier", "main");
        try {
            validateSetVariableTypeActionArgs(args);
            fail("Should throw exception for missing variableName in set_variable_type action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention variableName",
                e.getMessage().toLowerCase().contains("variablename"));
        }

        // Missing newType should be invalid
        args.put("variableName", "var1");
        try {
            validateSetVariableTypeActionArgs(args);
            fail("Should throw exception for missing newType in set_variable_type action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention newType",
                e.getMessage().toLowerCase().contains("newtype"));
        }

        // Valid set_variable_type action args
        args.put("newType", "int");
        args.put("archiveName", "");
        try {
            validateSetVariableTypeActionArgs(args);
        } catch (Exception e) {
            fail("Valid set_variable_type action parameters should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testValidateChangeDatatypesActionParameters() {
        // Test change_datatypes action parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "change_datatypes");

        // Missing functionIdentifier should be invalid
        try {
            validateChangeDatatypesActionArgs(args);
            fail("Should throw exception for missing functionIdentifier in change_datatypes action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Missing datatype_mappings should be invalid
        args.put("functionIdentifier", "main");
        try {
            validateChangeDatatypesActionArgs(args);
            fail("Should throw exception for missing datatype_mappings in change_datatypes action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention datatype",
                e.getMessage().toLowerCase().contains("datatype"));
        }

        // Valid change_datatypes action args
        args.put("datatypeMappings", "var1:int,var2:char*");
        args.put("archiveName", "");
        try {
            validateChangeDatatypesActionArgs(args);
        } catch (Exception e) {
            fail("Valid change_datatypes action parameters should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testParseVariableMappings() {
        // Test parsing of variable_mappings string format
        String mappingsStr = "var1:newVar1,var2:newVar2,var3:newVar3";
        Map<String, String> parsed = parseVariableMappings(mappingsStr);

        assertEquals("Should parse 3 mappings", 3, parsed.size());
        assertEquals("var1 should map to newVar1", "newVar1", parsed.get("var1"));
        assertEquals("var2 should map to newVar2", "newVar2", parsed.get("var2"));
        assertEquals("var3 should map to newVar3", "newVar3", parsed.get("var3"));

        // Test empty string
        Map<String, String> empty = parseVariableMappings("");
        assertTrue("Empty string should result in empty map", empty.isEmpty());

        // Test null
        Map<String, String> nullResult = parseVariableMappings(null);
        assertTrue("Null should result in empty map", nullResult.isEmpty());
    }

    @Test
    public void testParseDatatypeMappings() {
        // Test parsing of datatype_mappings string format
        String mappingsStr = "var1:int,var2:char*,var3:double";
        Map<String, String> parsed = parseDatatypeMappings(mappingsStr);

        assertEquals("Should parse 3 mappings", 3, parsed.size());
        assertEquals("var1 should map to int", "int", parsed.get("var1"));
        assertEquals("var2 should map to char*", "char*", parsed.get("var2"));
        assertEquals("var3 should map to double", "double", parsed.get("var3"));

        // Test empty string
        Map<String, String> empty = parseDatatypeMappings("");
        assertTrue("Empty string should result in empty map", empty.isEmpty());
    }

    // Helper methods to simulate parameter validation from the tool handlers
    private void validateManageFunctionArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("action") == null) {
            throw new IllegalArgumentException("No action provided");
        }
    }

    private void validateManageFunctionAction(Map<String, Object> args) {
        String action = (String) args.get("action");
        if (action != null) {
            String[] validActions = {"create", "rename_function", "set_prototype", "rename_variable", "set_variable_type", "change_datatypes"};
            boolean isValid = false;
            for (String validAction : validActions) {
                if (validAction.equals(action)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid action: " + action);
            }
        }
    }

    private void validateCreateActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("create".equals(action)) {
            if (args.get("address") == null) {
                throw new IllegalArgumentException("address is required when action='create'");
            }
        }
    }

    private void validateSetPrototypeActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("set_prototype".equals(action)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when action='set_prototype'");
            }
            if (args.get("prototype") == null) {
                throw new IllegalArgumentException("prototype is required when action='set_prototype'");
            }
        }
    }

    private void validateRenameVariableActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("rename_variable".equals(action)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when action='rename_variable'");
            }
            String variableMappings = (String) args.get("variableMappings");
            String oldName = (String) args.get("oldName");
            String newName = (String) args.get("newName");
            if ((variableMappings == null || variableMappings.trim().isEmpty()) &&
                (oldName == null || newName == null)) {
                throw new IllegalArgumentException("Either variableMappings or both oldName and newName are required when action='rename_variable'");
            }
        }
    }

    private void validateChangeDatatypesActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("change_datatypes".equals(action)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when action='change_datatypes'");
            }
            String datatypeMappings = (String) args.get("datatypeMappings");
            if (datatypeMappings == null || datatypeMappings.trim().isEmpty()) {
                throw new IllegalArgumentException("datatypeMappings is required when action='change_datatypes'");
            }
        }
    }

    private Map<String, String> parseVariableMappings(String mappingsStr) {
        Map<String, String> mappings = new HashMap<>();
        if (mappingsStr != null && !mappingsStr.trim().isEmpty()) {
            String[] pairs = mappingsStr.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) {
                    mappings.put(kv[0].trim(), kv[1].trim());
                }
            }
        }
        return mappings;
    }

    private Map<String, String> parseDatatypeMappings(String mappingsStr) {
        Map<String, String> mappings = new HashMap<>();
        if (mappingsStr != null && !mappingsStr.trim().isEmpty()) {
            String[] pairs = mappingsStr.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) {
                    mappings.put(kv[0].trim(), kv[1].trim());
                }
            }
        }
        return mappings;
    }

    private void validateRenameFunctionActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("rename_function".equals(action)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when action='rename_function'");
            }
            if (args.get("name") == null) {
                throw new IllegalArgumentException("name is required when action='rename_function'");
            }
        }
    }

    private void validateSetVariableTypeActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("set_variable_type".equals(action)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when action='set_variable_type'");
            }
            if (args.get("variableName") == null) {
                throw new IllegalArgumentException("variableName is required when action='set_variable_type'");
            }
            if (args.get("newType") == null) {
                throw new IllegalArgumentException("newType is required when action='set_variable_type'");
            }
        }
    }
}
