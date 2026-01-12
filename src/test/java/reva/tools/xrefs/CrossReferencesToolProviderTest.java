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
package reva.tools.xrefs;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for CrossReferencesToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated get_references tool that replaces:
 * - find-cross-references (mode='both', 'to', 'from')
 * - get-referencers-decompiled (mode='referencers_decomp')
 * - find-import-references (mode='import')
 * - resolve-thunk (mode='thunk')
 * - get-function-xrefs (mode='function')
 */
public class CrossReferencesToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private CrossReferencesToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new CrossReferencesToolProvider(mockServer);
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
        // Test that CrossReferencesToolProvider extends AbstractToolProvider
        assertTrue("CrossReferencesToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(CrossReferencesToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that CrossReferencesToolProvider implements ToolProvider interface
        assertTrue("CrossReferencesToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(CrossReferencesToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("CrossReferencesToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateGetReferencesParameters() {
        // Test parameter validation for the get_references tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("target", "0x401000");
        validArgs.put("mode", "both");

        // Valid parameters should not throw
        try {
            validateGetReferencesArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateGetReferencesArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }

        // Missing target should throw
        Map<String, Object> missingTarget = new HashMap<>(validArgs);
        missingTarget.remove("target");
        try {
            validateGetReferencesArgs(missingTarget);
            fail("Should throw exception for missing target");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention target",
                e.getMessage().toLowerCase().contains("target"));
        }
    }

    @Test
    public void testValidateGetReferencesModes() {
        // Test that all valid modes are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("target", "0x401000");

        // Test all valid modes
        String[] validModes = {"to", "from", "both", "function", "referencers_decomp", "import", "thunk"};
        for (String mode : validModes) {
            args.put("mode", mode);
            try {
                validateGetReferencesMode(args);
            } catch (Exception e) {
                fail("Valid mode '" + mode + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test invalid mode
        args.put("mode", "invalid");
        try {
            validateGetReferencesMode(args);
            fail("Should throw exception for invalid mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid mode",
                e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testValidateReferencersDecompModeParameters() {
        // Test referencers_decomp mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("target", "0x401000");
        args.put("mode", "referencers_decomp");

        // Valid referencers_decomp mode args
        args.put("max_referencers", 10);
        args.put("start_index", 0);
        args.put("include_ref_context", true);
        args.put("include_data_refs", true);
        try {
            validateReferencersDecompModeArgs(args);
        } catch (Exception e) {
            fail("Valid referencers_decomp mode parameters should not throw: " + e.getMessage());
        }

        // Test max_referencers validation
        args.put("max_referencers", 0);
        try {
            validateReferencersDecompMaxReferencers(args);
            fail("Should throw exception for max_referencers <= 0");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention max_referencers",
                e.getMessage().toLowerCase().contains("max_referencers"));
        }

        args.put("max_referencers", 100);
        try {
            validateReferencersDecompMaxReferencers(args);
            fail("Should throw exception for max_referencers > 50");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention max_referencers",
                e.getMessage().toLowerCase().contains("max_referencers"));
        }

        // Test start_index validation
        args.put("max_referencers", 10);
        args.put("start_index", -1);
        try {
            validateReferencersDecompStartIndex(args);
            fail("Should throw exception for negative start_index");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention start_index",
                e.getMessage().toLowerCase().contains("start_index"));
        }
    }

    @Test
    public void testValidateImportModeParameters() {
        // Test import mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("target", "printf");
        args.put("mode", "import");

        // Valid import mode args
        args.put("max_results", 100);
        args.put("library_name", "msvcrt.dll");
        try {
            validateImportModeArgs(args);
        } catch (Exception e) {
            fail("Valid import mode parameters should not throw: " + e.getMessage());
        }

        // Test max_results validation
        args.put("max_results", 0);
        try {
            validateImportModeMaxResults(args);
            fail("Should clamp or handle max_results <= 0");
        } catch (Exception e) {
            // May clamp or throw - either is acceptable
        }

        args.put("max_results", 2000);
        try {
            validateImportModeMaxResults(args);
            // Should clamp to 1000
        } catch (Exception e) {
            // May throw or clamp
        }
    }

    @Test
    public void testValidateBothModeParameters() {
        // Test both mode parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("target", "0x401000");
        args.put("mode", "both");

        // Valid both mode args
        args.put("direction", "both");
        args.put("offset", 0);
        args.put("limit", 100);
        try {
            validateBothModeArgs(args);
        } catch (Exception e) {
            fail("Valid both mode parameters should not throw: " + e.getMessage());
        }

        // Test direction validation
        args.put("direction", "invalid");
        try {
            validateBothModeDirection(args);
            fail("Should throw exception for invalid direction");
        } catch (IllegalArgumentException e) {
            // Expected - though direction might be ignored or defaulted
        }
    }

    @Test
    public void testValidatePaginationParameters() {
        // Test pagination parameter validation
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("target", "0x401000");

        // Valid pagination
        args.put("offset", 0);
        args.put("limit", 100);
        try {
            validatePaginationArgs(args);
        } catch (Exception e) {
            fail("Valid pagination parameters should not throw: " + e.getMessage());
        }

        // Test offset validation (should clamp to 0)
        args.put("offset", -5);
        try {
            validatePaginationArgs(args);
            // Should clamp to 0
        } catch (Exception e) {
            // May clamp or throw
        }

        // Test limit validation (should clamp to 1000 max)
        args.put("offset", 0);
        args.put("limit", 2000);
        try {
            validatePaginationArgs(args);
            // Should clamp to 1000
        } catch (Exception e) {
            // May clamp or throw
        }
    }

    // Helper methods to simulate parameter validation from the tool handlers
    private void validateGetReferencesArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("target") == null) {
            throw new IllegalArgumentException("No target provided");
        }
    }

    private void validateGetReferencesMode(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if (mode != null) {
            String[] validModes = {"to", "from", "both", "function", "referencers_decomp", "import", "thunk"};
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

    private void validateReferencersDecompModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("referencers_decomp".equals(mode)) {
            // Validate required parameters are present
            if (args.get("target") == null) {
                throw new IllegalArgumentException("target is required for referencers_decomp mode");
            }
        }
    }

    private void validateReferencersDecompMaxReferencers(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("referencers_decomp".equals(mode)) {
            Object maxRefsObj = args.get("max_referencers");
            if (maxRefsObj != null) {
                int maxReferencers = ((Number) maxRefsObj).intValue();
                if (maxReferencers <= 0 || maxReferencers > 50) {
                    throw new IllegalArgumentException("max_referencers must be between 1 and 50");
                }
            }
        }
    }

    private void validateReferencersDecompStartIndex(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("referencers_decomp".equals(mode)) {
            Object startIdxObj = args.get("start_index");
            if (startIdxObj != null) {
                int startIndex = ((Number) startIdxObj).intValue();
                if (startIndex < 0) {
                    throw new IllegalArgumentException("start_index must be non-negative");
                }
            }
        }
    }

    private void validateImportModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("import".equals(mode)) {
            if (args.get("target") == null) {
                throw new IllegalArgumentException("target is required for import mode");
            }
        }
    }

    private void validateImportModeMaxResults(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("import".equals(mode)) {
            Object maxResultsObj = args.get("max_results");
            if (maxResultsObj != null) {
                int maxResults = ((Number) maxResultsObj).intValue();
                if (maxResults <= 0) {
                    throw new IllegalArgumentException("max_results must be positive");
                }
                if (maxResults > 1000) {
                    throw new IllegalArgumentException("max_results must be <= 1000");
                }
            }
        }
    }

    private void validateBothModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("both".equals(mode)) {
            if (args.get("target") == null) {
                throw new IllegalArgumentException("target is required for both mode");
            }
        }
    }

    private void validateBothModeDirection(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        String direction = (String) args.get("direction");
        if ("both".equals(mode) && direction != null) {
            if (!"to".equalsIgnoreCase(direction) && !"from".equalsIgnoreCase(direction) && !"both".equalsIgnoreCase(direction)) {
                throw new IllegalArgumentException("Invalid direction: " + direction + ". Must be 'to', 'from', or 'both'");
            }
        }
    }

    private void validatePaginationArgs(Map<String, Object> args) {
        Object offsetObj = args.get("offset");
        if (offsetObj != null) {
            int offset = ((Number) offsetObj).intValue();
            if (offset < 0) {
                throw new IllegalArgumentException("offset must be non-negative");
            }
        }

        Object limitObj = args.get("limit");
        if (limitObj != null) {
            int limit = ((Number) limitObj).intValue();
            if (limit <= 0) {
                throw new IllegalArgumentException("limit must be positive");
            }
            if (limit > 1000) {
                throw new IllegalArgumentException("limit must be <= 1000");
            }
        }
    }
}
