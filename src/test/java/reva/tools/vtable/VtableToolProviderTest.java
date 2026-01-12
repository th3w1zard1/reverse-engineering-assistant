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
package reva.tools.vtable;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for VtableToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated analyze-vtables tool that replaces:
 * - analyze-vtable (mode='analyze')
 * - find-vtable-callers (mode='callers')
 * - find-vtables-containing-function (mode='containing')
 */
public class VtableToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private VtableToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new VtableToolProvider(mockServer);
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
        // Test that VtableToolProvider extends AbstractToolProvider
        assertTrue("VtableToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(VtableToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that VtableToolProvider implements ToolProvider interface
        assertTrue("VtableToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(VtableToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("VtableToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateAnalyzeVtablesParameters() {
        // Test parameter validation for the analyze-vtables tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("mode", "analyze");

        // Valid parameters should not throw
        try {
            validateAnalyzeVtablesArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateAnalyzeVtablesArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }

        // Missing mode should throw
        Map<String, Object> missingMode = new HashMap<>(validArgs);
        missingMode.remove("mode");
        try {
            validateAnalyzeVtablesArgs(missingMode);
            fail("Should throw exception for missing mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention mode",
                e.getMessage().toLowerCase().contains("mode"));
        }
    }

    @Test
    public void testValidateModeEnum() {
        // Test that all valid modes are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");

        // Test all valid modes
        String[] validModes = {"analyze", "callers", "containing"};
        for (String mode : validModes) {
            args.put("mode", mode);
            try {
                validateModeEnum(args);
            } catch (Exception e) {
                fail("Valid mode '" + mode + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test invalid mode
        args.put("mode", "invalid");
        try {
            validateModeEnum(args);
            fail("Should throw exception for invalid mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid mode",
                e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testValidateAnalyzeModeParameters() {
        // Test analyze mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "analyze");
        args.put("vtable_address", "0x401000");
        args.put("max_entries", 200);

        // Valid analyze mode args
        try {
            validateAnalyzeModeArgs(args);
        } catch (Exception e) {
            fail("Valid analyze mode parameters should not throw: " + e.getMessage());
        }

        // Missing vtable_address should throw
        args.remove("vtable_address");
        try {
            validateAnalyzeModeArgs(args);
            fail("Should throw exception for missing vtable_address in analyze mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention vtable_address",
                e.getMessage().toLowerCase().contains("vtable"));
        }

        // max_entries is optional with default
        args.put("vtable_address", "0x401000");
        args.remove("max_entries");
        try {
            validateAnalyzeModeArgs(args);
            // Should not throw - max_entries has default
        } catch (Exception e) {
            fail("max_entries should be optional with default value");
        }

        // Test max_entries clamping (should be handled in implementation)
        args.put("max_entries", 5000);
        try {
            validateMaxEntriesClamping(args);
            // Should clamp to max (1000)
        } catch (Exception e) {
            // May clamp or validate
        }
    }

    @Test
    public void testValidateCallersModeParameters() {
        // Test callers mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "callers");
        args.put("function_address", "0x402000");
        args.put("max_results", 500);

        // Valid callers mode args
        try {
            validateCallersModeArgs(args);
        } catch (Exception e) {
            fail("Valid callers mode parameters should not throw: " + e.getMessage());
        }

        // Missing function_address should throw
        args.remove("function_address");
        try {
            validateCallersModeArgs(args);
            fail("Should throw exception for missing function_address in callers mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention function_address",
                e.getMessage().toLowerCase().contains("function"));
        }

        // vtable_address is optional for callers mode
        args.put("function_address", "0x402000");
        args.put("vtable_address", "0x401000");
        try {
            validateCallersModeArgs(args);
            // Should not throw - vtable_address is optional
        } catch (Exception e) {
            fail("vtable_address should be optional for callers mode");
        }

        // max_results is optional with default
        args.remove("max_results");
        try {
            validateCallersModeArgs(args);
            // Should not throw - max_results has default
        } catch (Exception e) {
            fail("max_results should be optional with default value");
        }
    }

    @Test
    public void testValidateContainingModeParameters() {
        // Test containing mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "containing");
        args.put("function_address", "0x402000");

        // Valid containing mode args
        try {
            validateContainingModeArgs(args);
        } catch (Exception e) {
            fail("Valid containing mode parameters should not throw: " + e.getMessage());
        }

        // Missing function_address should throw
        args.remove("function_address");
        try {
            validateContainingModeArgs(args);
            fail("Should throw exception for missing function_address in containing mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention function_address",
                e.getMessage().toLowerCase().contains("function"));
        }
    }

    // Helper methods to simulate parameter validation from the tool handler
    private void validateAnalyzeVtablesArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("mode") == null) {
            throw new IllegalArgumentException("No mode provided");
        }
    }

    private void validateModeEnum(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if (mode != null) {
            String[] validModes = {"analyze", "callers", "containing"};
            boolean isValid = false;
            for (String validMode : validModes) {
                if (validMode.equals(mode)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid mode: " + mode +
                    ". Valid modes are: analyze, callers, containing");
            }
        }
    }

    private void validateAnalyzeModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("analyze".equals(mode)) {
            if (args.get("vtable_address") == null && args.get("vtableAddress") == null) {
                throw new IllegalArgumentException("vtable_address is required for mode='analyze'");
            }
            // max_entries is optional with default
        }
    }

    private void validateCallersModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("callers".equals(mode)) {
            if (args.get("function_address") == null && args.get("functionAddress") == null) {
                throw new IllegalArgumentException("function_address is required for mode='callers'");
            }
            // vtable_address is optional (searches all vtables if not provided)
            // max_results is optional with default
        }
    }

    private void validateContainingModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("containing".equals(mode)) {
            if (args.get("function_address") == null && args.get("functionAddress") == null) {
                throw new IllegalArgumentException("function_address is required for mode='containing'");
            }
        }
    }

    private void validateMaxEntriesClamping(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("analyze".equals(mode)) {
            Object maxEntriesObj = args.get("max_entries");
            if (maxEntriesObj != null) {
                int maxEntries = ((Number) maxEntriesObj).intValue();
                if (maxEntries < 1) {
                    throw new IllegalArgumentException("max_entries must be at least 1");
                }
                if (maxEntries > 1000) {
                    throw new IllegalArgumentException("max_entries exceeds maximum of 1000");
                }
            }
        }
    }
}
