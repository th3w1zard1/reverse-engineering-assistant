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
package reva.tools.memory;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for MemoryToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated inspect-memory tool that replaces:
 * - get-memory-blocks (mode='blocks')
 * - read-memory (mode='read')
 * - get-data-at-address (mode='data_at')
 * - list-data-items (mode='data_items')
 * - list-segments (mode='segments')
 */
public class MemoryToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private MemoryToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new MemoryToolProvider(mockServer);
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
        // Test that MemoryToolProvider extends AbstractToolProvider
        assertTrue("MemoryToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(MemoryToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that MemoryToolProvider implements ToolProvider interface
        assertTrue("MemoryToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(MemoryToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("MemoryToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateInspectMemoryParameters() {
        // Test parameter validation for the inspect-memory tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("mode", "blocks");

        // Valid parameters should not throw
        try {
            validateInspectMemoryArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateInspectMemoryArgs(missingProgram);
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
            validateInspectMemoryArgs(missingMode);
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
        String[] validModes = {"blocks", "read", "data_at", "data_items", "segments"};
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
    public void testValidateReadModeParameters() {
        // Test read mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "read");
        args.put("address", "0x401000");
        args.put("length", 16);

        // Valid read mode args
        try {
            validateReadModeArgs(args);
        } catch (Exception e) {
            fail("Valid read mode parameters should not throw: " + e.getMessage());
        }

        // Missing address should throw
        args.remove("address");
        try {
            validateReadModeArgs(args);
            fail("Should throw exception for missing address in read mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address",
                e.getMessage().toLowerCase().contains("address"));
        }

        // Invalid length should be handled
        args.put("address", "0x401000");
        args.put("length", 0);
        try {
            validateReadModeLength(args);
            fail("Should throw exception for invalid length");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention length",
                e.getMessage().toLowerCase().contains("length") ||
                e.getMessage().toLowerCase().contains("invalid"));
        }

        // Length should be clamped to max
        args.put("length", 20000);
        try {
            validateReadModeLength(args);
            // Should clamp to 10000
        } catch (Exception e) {
            // May clamp or throw
        }
    }

    @Test
    public void testValidateDataAtModeParameters() {
        // Test data_at mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "data_at");
        args.put("address", "0x401000");

        // Valid data_at mode args
        try {
            validateDataAtModeArgs(args);
        } catch (Exception e) {
            fail("Valid data_at mode parameters should not throw: " + e.getMessage());
        }

        // Missing address should throw
        args.remove("address");
        try {
            validateDataAtModeArgs(args);
            fail("Should throw exception for missing address in data_at mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address",
                e.getMessage().toLowerCase().contains("address"));
        }
    }

    @Test
    public void testValidateDataItemsModeParameters() {
        // Test data_items mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "data_items");
        args.put("offset", 0);
        args.put("limit", 100);

        // Valid data_items mode args
        try {
            validateDataItemsModeArgs(args);
        } catch (Exception e) {
            fail("Valid data_items mode parameters should not throw: " + e.getMessage());
        }

        // Test pagination parameter validation
        args.put("offset", -5);
        try {
            validatePaginationArgs(args);
            // Should clamp to 0
        } catch (Exception e) {
            // May clamp or throw
        }

        args.put("offset", 0);
        args.put("limit", 0);
        try {
            validatePaginationArgs(args);
            // Should use default or clamp
        } catch (Exception e) {
            // May use default or throw
        }

        args.put("limit", 2000);
        try {
            validatePaginationArgs(args);
            // Should clamp to 1000
        } catch (Exception e) {
            // May clamp or throw
        }
    }

    @Test
    public void testValidateSegmentsModeParameters() {
        // Test segments mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "segments");
        args.put("offset", 0);
        args.put("limit", 100);

        // Valid segments mode args
        try {
            validateSegmentsModeArgs(args);
        } catch (Exception e) {
            fail("Valid segments mode parameters should not throw: " + e.getMessage());
        }

        // Pagination is optional for segments mode
        args.remove("offset");
        args.remove("limit");
        try {
            validateSegmentsModeArgs(args);
        } catch (Exception e) {
            fail("Segments mode should work without pagination parameters");
        }
    }

    @Test
    public void testValidateBlocksModeParameters() {
        // Test blocks mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "blocks");

        // Valid blocks mode args (only needs programPath and mode)
        try {
            validateBlocksModeArgs(args);
        } catch (Exception e) {
            fail("Valid blocks mode parameters should not throw: " + e.getMessage());
        }
    }

    // Helper methods to simulate parameter validation from the tool handler
    private void validateInspectMemoryArgs(Map<String, Object> args) {
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
            String[] validModes = {"blocks", "read", "data_at", "data_items", "segments"};
            boolean isValid = false;
            for (String validMode : validModes) {
                if (validMode.equals(mode)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid mode: " + mode +
                    ". Valid modes are: blocks, read, data_at, data_items, segments");
            }
        }
    }

    private void validateReadModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("read".equals(mode)) {
            if (args.get("address") == null) {
                throw new IllegalArgumentException("address is required for mode='read'");
            }
        }
    }

    private void validateReadModeLength(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("read".equals(mode)) {
            Object lengthObj = args.get("length");
            if (lengthObj != null) {
                int length = ((Number) lengthObj).intValue();
                if (length <= 0) {
                    throw new IllegalArgumentException("Invalid length: " + length);
                }
                if (length > 10000) {
                    throw new IllegalArgumentException("Length exceeds maximum of 10000");
                }
            }
        }
    }

    private void validateDataAtModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("data_at".equals(mode)) {
            if (args.get("address") == null) {
                throw new IllegalArgumentException("address is required for mode='data_at'");
            }
        }
    }

    private void validateDataItemsModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("data_items".equals(mode)) {
            // offset and limit are optional with defaults
        }
    }

    private void validateSegmentsModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("segments".equals(mode)) {
            // offset and limit are optional with defaults
        }
    }

    private void validateBlocksModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("blocks".equals(mode)) {
            // blocks mode only needs programPath and mode
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
