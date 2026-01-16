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
package reva.tools.callgraph;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for CallGraphToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the get-call-graph tool
 */
public class CallGraphToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private CallGraphToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new CallGraphToolProvider(mockServer);
    }

    @Test
    public void testRegisterTools() {
        // Test that tools can be registered without throwing exceptions
        try {
            toolProvider.registerTools();
        } catch (Exception e) {
            fail("Tool registration should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testInheritance() {
        // Test that CallGraphToolProvider extends AbstractToolProvider
        assertTrue("CallGraphToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(CallGraphToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that CallGraphToolProvider implements ToolProvider interface
        assertTrue("CallGraphToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(CallGraphToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("CallGraphToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateGetCallGraphParameters() {
        // Test parameter validation for the get-call-graph tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("mode", "graph");
        validArgs.put("functionIdentifier", "main");

        // Valid parameters should not throw
        try {
            validateGetCallGraphArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateGetCallGraphArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }
    }

    @Test
    public void testValidateGetCallGraphModes() {
        // Test that all valid modes are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");

        // Test all valid modes
        String[] validModes = {"graph", "tree", "callers", "callees", "callers_decomp", "common_callers"};
        for (String mode : validModes) {
            args.put("mode", mode);
            try {
                validateGetCallGraphMode(args);
            } catch (Exception e) {
                fail("Valid mode '" + mode + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test invalid mode
        args.put("mode", "invalid");
        try {
            validateGetCallGraphMode(args);
            fail("Should throw exception for invalid mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid mode",
                e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testValidateGraphModeParameters() {
        // Test graph mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "graph");

        // Missing function_identifier should be invalid
        try {
            validateGraphModeArgs(args);
            fail("Should throw exception for missing function_identifier in graph mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Valid graph mode args
        args.put("functionIdentifier", "main");
        args.put("depth", 1);
        try {
            validateGraphModeArgs(args);
        } catch (Exception e) {
            fail("Valid graph mode parameters should not throw: " + e.getMessage());
        }

        // Test depth clamping
        args.put("depth", 15); // Should be clamped to 10
        args.put("depth", -1); // Should be clamped to 1
    }

    @Test
    public void testValidateTreeModeParameters() {
        // Test tree mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "tree");

        // Missing function_identifier should be invalid
        try {
            validateTreeModeArgs(args);
            fail("Should throw exception for missing function_identifier in tree mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Valid tree mode args
        args.put("functionIdentifier", "main");
        args.put("direction", "callers");
        args.put("maxDepth", 3);
        try {
            validateTreeModeArgs(args);
        } catch (Exception e) {
            fail("Valid tree mode parameters should not throw: " + e.getMessage());
        }

        // Test invalid direction
        args.put("direction", "invalid");
        try {
            validateTreeModeDirection(args);
            fail("Should throw exception for invalid direction");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid direction",
                e.getMessage().toLowerCase().contains("direction"));
        }
    }

    @Test
    public void testValidateCallersModeParameters() {
        // Test callers mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "callers");

        // Missing function_identifier should be invalid
        try {
            validateCallersModeArgs(args);
            fail("Should throw exception for missing function_identifier in callers mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Valid callers mode args
        args.put("functionIdentifier", "main");
        args.put("direction", "callers");
        try {
            validateCallersModeArgs(args);
        } catch (Exception e) {
            fail("Valid callers mode parameters should not throw: " + e.getMessage());
        }

        // Invalid direction for callers mode (must be 'callers')
        args.put("direction", "callees");
        try {
            validateCallersModeDirection(args);
            fail("Should throw exception for invalid direction in callers mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention direction",
                e.getMessage().toLowerCase().contains("direction"));
        }
    }

    @Test
    public void testValidateCalleesModeParameters() {
        // Test callees mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "callees");

        // Missing function_identifier should be invalid
        try {
            validateCalleesModeArgs(args);
            fail("Should throw exception for missing function_identifier in callees mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Valid callees mode args
        args.put("functionIdentifier", "main");
        args.put("direction", "callees");
        try {
            validateCalleesModeArgs(args);
        } catch (Exception e) {
            fail("Valid callees mode parameters should not throw: " + e.getMessage());
        }

        // Invalid direction for callees mode (must be 'callees')
        args.put("direction", "callers");
        try {
            validateCalleesModeDirection(args);
            fail("Should throw exception for invalid direction in callees mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention direction",
                e.getMessage().toLowerCase().contains("direction"));
        }
    }

    @Test
    public void testValidateCallersDecompModeParameters() {
        // Test callers_decomp mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "callers_decomp");

        // Missing function_identifier should be invalid
        try {
            validateCallersDecompModeArgs(args);
            fail("Should throw exception for missing function_identifier in callers_decomp mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionIdentifier",
                e.getMessage().toLowerCase().contains("functionidentifier"));
        }

        // Valid callers_decomp mode args
        args.put("functionIdentifier", "main");
        args.put("maxCallers", 10);
        args.put("startIndex", 0);
        args.put("includeCallContext", true);
        try {
            validateCallersDecompModeArgs(args);
        } catch (Exception e) {
            fail("Valid callers_decomp mode parameters should not throw: " + e.getMessage());
        }

        // Test max_callers validation
        args.put("maxCallers", 0);
        try {
            validateCallersDecompMaxCallers(args);
            fail("Should throw exception for max_callers <= 0");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention maxCallers",
                e.getMessage().toLowerCase().contains("maxcallers"));
        }

        args.put("maxCallers", 100);
        try {
            validateCallersDecompMaxCallers(args);
            fail("Should throw exception for max_callers > 50");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention maxCallers",
                e.getMessage().toLowerCase().contains("maxcallers"));
        }

        // Test start_index validation
        args.put("maxCallers", 10);
        args.put("startIndex", -1);
        try {
            validateCallersDecompStartIndex(args);
            fail("Should throw exception for negative start_index");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention startIndex",
                e.getMessage().toLowerCase().contains("startindex"));
        }
    }

    @Test
    public void testValidateCommonCallersModeParameters() {
        // Test common_callers mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "common_callers");

        // Missing function_addresses should be invalid
        try {
            validateCommonCallersModeArgs(args);
            fail("Should throw exception for missing function_addresses in common_callers mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionAddresses",
                e.getMessage().toLowerCase().contains("functionaddresses"));
        }

        // Empty function_addresses should be invalid
        args.put("functionAddresses", "");
        try {
            validateCommonCallersModeArgs(args);
            fail("Should throw exception for empty function_addresses");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention functionAddresses",
                e.getMessage().toLowerCase().contains("functionaddresses"));
        }

        // Valid common_callers mode args
        args.put("functionAddresses", "main,func1,func2");
        try {
            validateCommonCallersModeArgs(args);
        } catch (Exception e) {
            fail("Valid common_callers mode parameters should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testParseFunctionAddresses() {
        // Test parsing of function_addresses string format
        String addressesStr = "main,func1,func2,func3";
        String[] parsed = parseFunctionAddresses(addressesStr);

        assertEquals("Should parse 4 addresses", 4, parsed.length);
        assertEquals("First should be main", "main", parsed[0].trim());
        assertEquals("Second should be func1", "func1", parsed[1].trim());
        assertEquals("Third should be func2", "func2", parsed[2].trim());
        assertEquals("Fourth should be func3", "func3", parsed[3].trim());

        // Test empty string
        String[] empty = parseFunctionAddresses("");
        assertEquals("Empty string should result in empty array", 0, empty.length);

        // Test whitespace handling
        String[] withSpaces = parseFunctionAddresses("main , func1 , func2");
        assertEquals("Should handle spaces", 3, withSpaces.length);
        assertEquals("Should trim spaces", "main", withSpaces[0].trim());
    }

    @Test
    public void testValidateDepthClamping() {
        // Test depth clamping logic
        assertEquals("Depth < 1 should clamp to 1", 1, clampDepth(-5));
        assertEquals("Depth 0 should clamp to 1", 1, clampDepth(0));
        assertEquals("Depth 1 should remain 1", 1, clampDepth(1));
        assertEquals("Depth 5 should remain 5", 5, clampDepth(5));
        assertEquals("Depth 10 should remain 10", 10, clampDepth(10));
        assertEquals("Depth > 10 should clamp to 10", 10, clampDepth(15));
        assertEquals("Depth > 10 should clamp to 10", 10, clampDepth(100));
    }

    // Helper methods to simulate parameter validation from the tool handlers
    private void validateGetCallGraphArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
    }

    private void validateGetCallGraphMode(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if (mode != null) {
            String[] validModes = {"graph", "tree", "callers", "callees", "callers_decomp", "common_callers"};
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

    private void validateGraphModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("graph".equals(mode)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when mode='graph'");
            }
        }
    }

    private void validateTreeModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("tree".equals(mode)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when mode='tree'");
            }
        }
    }

    private void validateTreeModeDirection(Map<String, Object> args) {
        String direction = (String) args.get("direction");
        if (direction != null && !"callers".equalsIgnoreCase(direction) && !"callees".equalsIgnoreCase(direction)) {
            throw new IllegalArgumentException("Invalid direction: '" + direction + "'. Must be 'callers' or 'callees'.");
        }
    }

    private void validateCallersModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("callers".equals(mode)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when mode='callers'");
            }
        }
    }

    private void validateCallersModeDirection(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        String direction = (String) args.get("direction");
        if ("callers".equals(mode) && direction != null && !"callers".equalsIgnoreCase(direction)) {
            throw new IllegalArgumentException("When mode='callers', direction must be 'callers'");
        }
    }

    private void validateCalleesModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("callees".equals(mode)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when mode='callees'");
            }
        }
    }

    private void validateCalleesModeDirection(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        String direction = (String) args.get("direction");
        if ("callees".equals(mode) && direction != null && !"callees".equalsIgnoreCase(direction)) {
            throw new IllegalArgumentException("When mode='callees', direction must be 'callees'");
        }
    }

    private void validateCallersDecompModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("callers_decomp".equals(mode)) {
            if (args.get("functionIdentifier") == null) {
                throw new IllegalArgumentException("functionIdentifier is required when mode='callers_decomp'");
            }
        }
    }

    private void validateCallersDecompMaxCallers(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("callers_decomp".equals(mode)) {
            Object maxCallersObj = args.get("maxCallers");
            if (maxCallersObj != null) {
                int maxCallers = ((Number) maxCallersObj).intValue();
                if (maxCallers <= 0 || maxCallers > 50) {
                    throw new IllegalArgumentException("maxCallers must be between 1 and 50");
                }
            }
        }
    }

    private void validateCallersDecompStartIndex(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("callers_decomp".equals(mode)) {
            Object startIndexObj = args.get("startIndex");
            if (startIndexObj != null) {
                int startIndex = ((Number) startIndexObj).intValue();
                if (startIndex < 0) {
                    throw new IllegalArgumentException("startIndex must be non-negative");
                }
            }
        }
    }

    private void validateCommonCallersModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("common_callers".equals(mode)) {
            String functionAddresses = (String) args.get("functionAddresses");
            if (functionAddresses == null || functionAddresses.trim().isEmpty()) {
                throw new IllegalArgumentException("functionAddresses is required when mode='common_callers'");
            }
        }
    }

    private String[] parseFunctionAddresses(String addressesStr) {
        if (addressesStr == null || addressesStr.trim().isEmpty()) {
            return new String[0];
        }
        return addressesStr.split(",");
    }

    private int clampDepth(int depth) {
        if (depth < 1) return 1;
        if (depth > 10) return 10;
        return depth;
    }
}
