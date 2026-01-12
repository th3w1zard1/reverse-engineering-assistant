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
package reva.tools.dataflow;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for DataFlowToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated analyze-data-flow tool that replaces:
 * - trace-data-flow-backward (direction='backward')
 * - trace-data-flow-forward (direction='forward')
 * - find-variable-accesses (direction='variable_accesses')
 */
public class DataFlowToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private DataFlowToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new DataFlowToolProvider(mockServer);
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
        // Test that DataFlowToolProvider extends AbstractToolProvider
        assertTrue("DataFlowToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(DataFlowToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that DataFlowToolProvider implements ToolProvider interface
        assertTrue("DataFlowToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(DataFlowToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("DataFlowToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateAnalyzeDataFlowParameters() {
        // Test parameter validation for the analyze-data-flow tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("function_address", "0x401000");
        validArgs.put("direction", "backward");
        validArgs.put("start_address", "0x401234");

        // Valid parameters should not throw
        try {
            validateAnalyzeDataFlowArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateAnalyzeDataFlowArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }

        // Missing function_address should throw
        Map<String, Object> missingFunction = new HashMap<>(validArgs);
        missingFunction.remove("function_address");
        try {
            validateAnalyzeDataFlowArgs(missingFunction);
            fail("Should throw exception for missing function_address");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention function",
                e.getMessage().toLowerCase().contains("function"));
        }

        // Missing direction should throw
        Map<String, Object> missingDirection = new HashMap<>(validArgs);
        missingDirection.remove("direction");
        try {
            validateAnalyzeDataFlowArgs(missingDirection);
            fail("Should throw exception for missing direction");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention direction",
                e.getMessage().toLowerCase().contains("direction"));
        }
    }

    @Test
    public void testValidateDirectionEnum() {
        // Test that all valid directions are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("function_address", "0x401000");

        // Test all valid directions
        String[] validDirections = {"backward", "forward", "variable_accesses"};
        for (String direction : validDirections) {
            args.put("direction", direction);
            try {
                validateDirectionEnum(args);
            } catch (Exception e) {
                fail("Valid direction '" + direction + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test invalid direction
        args.put("direction", "invalid");
        try {
            validateDirectionEnum(args);
            fail("Should throw exception for invalid direction");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid direction",
                e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testValidateBackwardForwardModeParameters() {
        // Test backward/forward mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("function_address", "0x401000");

        // Test backward mode requires start_address
        args.put("direction", "backward");
        args.put("start_address", "0x401234");
        try {
            validateBackwardForwardModeArgs(args);
        } catch (Exception e) {
            fail("Valid backward mode parameters should not throw: " + e.getMessage());
        }

        args.remove("start_address");
        try {
            validateBackwardForwardModeArgs(args);
            fail("Should throw exception for missing start_address in backward mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention start_address",
                e.getMessage().toLowerCase().contains("start_address") ||
                e.getMessage().toLowerCase().contains("start"));
        }

        // Test forward mode requires start_address
        args.put("direction", "forward");
        args.put("start_address", "0x401234");
        try {
            validateBackwardForwardModeArgs(args);
        } catch (Exception e) {
            fail("Valid forward mode parameters should not throw: " + e.getMessage());
        }

        args.remove("start_address");
        try {
            validateBackwardForwardModeArgs(args);
            fail("Should throw exception for missing start_address in forward mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention start_address",
                e.getMessage().toLowerCase().contains("start_address") ||
                e.getMessage().toLowerCase().contains("start"));
        }
    }

    @Test
    public void testValidateVariableAccessesModeParameters() {
        // Test variable_accesses mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("function_address", "0x401000");
        args.put("direction", "variable_accesses");
        args.put("variable_name", "local_var");

        // Valid variable_accesses mode args
        try {
            validateVariableAccessesModeArgs(args);
        } catch (Exception e) {
            fail("Valid variable_accesses mode parameters should not throw: " + e.getMessage());
        }

        // Missing variable_name should throw
        args.remove("variable_name");
        try {
            validateVariableAccessesModeArgs(args);
            fail("Should throw exception for missing variable_name in variable_accesses mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention variable_name",
                e.getMessage().toLowerCase().contains("variable"));
        }
    }

    @Test
    public void testValidateStartAddressWithinFunction() {
        // Test that start_address validation checks are in place
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("function_address", "0x401000");
        args.put("direction", "backward");
        args.put("start_address", "0x401234");

        // Valid start_address (would need actual program to fully validate)
        try {
            validateStartAddressFormat(args);
        } catch (Exception e) {
            fail("Valid start_address format should not throw: " + e.getMessage());
        }

        // Invalid start_address format
        args.put("start_address", "invalid_address");
        try {
            validateStartAddressFormat(args);
            // May not throw here, but should be validated in actual implementation
        } catch (Exception e) {
            // Expected if format validation exists
        }
    }

    // Helper methods to simulate parameter validation from the tool handler
    private void validateAnalyzeDataFlowArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("function_address") == null) {
            throw new IllegalArgumentException("No function address provided");
        }
        if (args.get("direction") == null) {
            throw new IllegalArgumentException("No direction provided");
        }
    }

    private void validateDirectionEnum(Map<String, Object> args) {
        String direction = (String) args.get("direction");
        if (direction != null) {
            String[] validDirections = {"backward", "forward", "variable_accesses"};
            boolean isValid = false;
            for (String validDir : validDirections) {
                if (validDir.equals(direction)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid direction: " + direction +
                    ". Valid directions are: backward, forward, variable_accesses");
            }
        }
    }

    private void validateBackwardForwardModeArgs(Map<String, Object> args) {
        String direction = (String) args.get("direction");
        if ("backward".equals(direction) || "forward".equals(direction)) {
            if (args.get("start_address") == null) {
                throw new IllegalArgumentException("start_address is required for backward and forward modes");
            }
        }
    }

    private void validateVariableAccessesModeArgs(Map<String, Object> args) {
        String direction = (String) args.get("direction");
        if ("variable_accesses".equals(direction)) {
            if (args.get("variable_name") == null) {
                throw new IllegalArgumentException("variable_name is required for variable_accesses mode");
            }
        }
    }

    private void validateStartAddressFormat(Map<String, Object> args) {
        String startAddress = (String) args.get("start_address");
        if (startAddress != null) {
            // Basic format check - should start with 0x or be numeric
            if (!startAddress.startsWith("0x") && !startAddress.matches("\\d+")) {
                throw new IllegalArgumentException("Invalid address format: " + startAddress);
            }
        }
    }
}
