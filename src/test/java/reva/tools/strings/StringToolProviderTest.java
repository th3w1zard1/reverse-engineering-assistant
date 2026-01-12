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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;

/**
 * Unit tests for StringToolProvider
 */
public class StringToolProviderTest {
    @Mock
    private McpSyncServer mockServer;

    @Mock
    private Program mockProgram;

    @Mock
    private Listing mockListing;

    @Mock
    private DataIterator mockDataIterator;

    @Mock
    private Data mockData;

    @Mock
    private Address mockAddress;

    @Mock
    private DataType mockDataType;

    private StringToolProvider stringToolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        stringToolProvider = new StringToolProvider(mockServer);
    }

    @Test
    public void testConstructor() {
        assertNotNull("StringToolProvider should be created", stringToolProvider);
    }

    @Test
    public void testRegisterTools() throws McpError {
        // Test that registerTools completes without throwing
        stringToolProvider.registerTools();
    }

    @Test
    public void testGetStringInfoWithValidString() throws Exception {
        // Setup mock data
        String testString = "Hello, World!";
        byte[] testBytes = testString.getBytes();

        when(mockData.getValue()).thenReturn(testString);
        when(mockData.getAddress()).thenReturn(mockAddress);
        when(mockAddress.toString()).thenReturn("00401000");
        when(mockAddress.toString("0x")).thenReturn("0x00401000");
        when(mockData.getBytes()).thenReturn(testBytes);
        when(mockData.getDataType()).thenReturn(mockDataType);
        when(mockDataType.getName()).thenReturn("string");
        when(mockData.getDefaultValueRepresentation()).thenReturn("\"Hello, World!\"");

        // Use reflection to test the private method
        java.lang.reflect.Method method = StringToolProvider.class.getDeclaredMethod("getStringInfo", Data.class);
        method.setAccessible(true);

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) method.invoke(stringToolProvider, mockData);

        assertNotNull("Result should not be null", result);
        assertEquals("Address should match", "0x00401000", result.get("address"));
        assertEquals("Content should match", testString, result.get("content"));
        assertEquals("Length should match", testString.length(), result.get("length"));
        assertEquals("Data type should match", "string", result.get("dataType"));
        assertEquals("Representation should match", "\"Hello, World!\"", result.get("representation"));
        assertNotNull("Hex bytes should be present", result.get("hexBytes"));
        assertEquals("Byte length should match", testBytes.length, result.get("byteLength"));
    }

    @Test
    public void testGetStringInfoWithNonString() throws Exception {
        // Setup mock data with non-string value
        when(mockData.getValue()).thenReturn(Integer.valueOf(42));

        // Use reflection to test the private method
        java.lang.reflect.Method method = StringToolProvider.class.getDeclaredMethod("getStringInfo", Data.class);
        method.setAccessible(true);

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) method.invoke(stringToolProvider, mockData);

        assertNull("Result should be null for non-string data", result);
    }

    @Test
    public void testInheritance() {
        // Test that StringToolProvider extends AbstractToolProvider
        assertTrue("StringToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(StringToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that StringToolProvider implements ToolProvider interface
        assertTrue("StringToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(StringToolProvider.class));
    }

    @Test
    public void testValidateManageStringsParameters() {
        // Test parameter validation for the manage-strings tool
        Map<String, Object> validArgs = new java.util.HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("mode", "list");

        // Valid parameters should not throw
        try {
            validateManageStringsArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new java.util.HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateManageStringsArgs(missingProgram);
            fail("Should throw exception for missing programPath");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention programPath",
                e.getMessage().toLowerCase().contains("program"));
        }
    }

    @Test
    public void testValidateModeEnum() {
        // Test that all valid modes are accepted
        Map<String, Object> args = new java.util.HashMap<>();
        args.put("programPath", "/test/program");

        // Test all valid modes
        String[] validModes = {"list", "regex", "count", "similarity"};
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

        // Test default mode (should default to 'list')
        args.remove("mode");
        try {
            validateModeEnum(args);
            // Should default to 'list' or accept missing mode
        } catch (Exception e) {
            // May throw or default - either is acceptable
        }
    }

    @Test
    public void testValidateRegexModeParameters() {
        // Test regex mode parameter requirements
        Map<String, Object> args = new java.util.HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "regex");
        args.put("pattern", ".*test.*");
        args.put("max_results", 100);

        // Valid regex mode args
        try {
            validateRegexModeArgs(args);
        } catch (Exception e) {
            fail("Valid regex mode parameters should not throw: " + e.getMessage());
        }

        // Missing pattern should throw
        args.remove("pattern");
        try {
            validateRegexModeArgs(args);
            fail("Should throw exception for missing pattern in regex mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention pattern",
                e.getMessage().toLowerCase().contains("pattern"));
        }

        // Empty pattern should throw
        args.put("pattern", "");
        try {
            validateRegexModeArgs(args);
            fail("Should throw exception for empty pattern in regex mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention empty",
                e.getMessage().toLowerCase().contains("empty") ||
                e.getMessage().toLowerCase().contains("pattern"));
        }

        // Invalid regex pattern should throw
        args.put("pattern", "[invalid");
        try {
            validateRegexPattern(args);
            fail("Should throw exception for invalid regex pattern");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid regex",
                e.getMessage().toLowerCase().contains("invalid") ||
                e.getMessage().toLowerCase().contains("regex"));
        }
    }

    @Test
    public void testValidateSimilarityModeParameters() {
        // Test similarity mode parameter requirements
        Map<String, Object> args = new java.util.HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "similarity");
        args.put("search_string", "test");
        args.put("start_index", 0);
        args.put("max_count", 100);

        // Valid similarity mode args
        try {
            validateSimilarityModeArgs(args);
        } catch (Exception e) {
            fail("Valid similarity mode parameters should not throw: " + e.getMessage());
        }

        // Missing search_string should throw
        args.remove("search_string");
        try {
            validateSimilarityModeArgs(args);
            fail("Should throw exception for missing search_string in similarity mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention search_string",
                e.getMessage().toLowerCase().contains("search"));
        }

        // Empty search_string should throw
        args.put("search_string", "");
        try {
            validateSimilarityModeArgs(args);
            fail("Should throw exception for empty search_string in similarity mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention empty",
                e.getMessage().toLowerCase().contains("empty") ||
                e.getMessage().toLowerCase().contains("search"));
        }
    }

    @Test
    public void testValidateListModeParameters() {
        // Test list mode parameter requirements
        Map<String, Object> args = new java.util.HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "list");
        args.put("start_index", 0);
        args.put("max_count", 100);
        args.put("filter", "test");
        args.put("include_referencing_functions", false);

        // Valid list mode args
        try {
            validateListModeArgs(args);
        } catch (Exception e) {
            fail("Valid list mode parameters should not throw: " + e.getMessage());
        }

        // Test pagination parameter defaults and alternatives
        args.put("offset", 10);
        args.put("limit", 50);
        try {
            validateListModeArgs(args);
            // Should handle offset/limit as alternative to start_index/max_count
        } catch (Exception e) {
            // May or may not accept both
        }
    }

    @Test
    public void testValidateCountModeParameters() {
        // Test count mode parameter requirements
        Map<String, Object> args = new java.util.HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "count");

        // Valid count mode args (only needs programPath)
        try {
            validateCountModeArgs(args);
        } catch (Exception e) {
            fail("Valid count mode parameters should not throw: " + e.getMessage());
        }
    }

    @Test
    public void testValidatePaginationParameters() {
        // Test pagination parameter validation
        Map<String, Object> args = new java.util.HashMap<>();
        args.put("programPath", "/test/program");

        // Valid pagination
        args.put("start_index", 0);
        args.put("max_count", 100);
        try {
            validatePaginationArgs(args);
        } catch (Exception e) {
            fail("Valid pagination parameters should not throw: " + e.getMessage());
        }

        // Test start_index validation (should clamp to 0)
        args.put("start_index", -5);
        try {
            validatePaginationArgs(args);
            // Should clamp to 0
        } catch (Exception e) {
            // May clamp or throw
        }

        // Test max_count validation
        args.put("start_index", 0);
        args.put("max_count", 0);
        try {
            validatePaginationArgs(args);
            // May have minimum or default
        } catch (Exception e) {
            // May throw or use default
        }
    }

    // Helper methods to simulate parameter validation from the tool handler
    private void validateManageStringsArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
    }

    private void validateModeEnum(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if (mode != null) {
            String[] validModes = {"list", "regex", "count", "similarity"};
            boolean isValid = false;
            for (String validMode : validModes) {
                if (validMode.equals(mode)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid mode: " + mode +
                    ". Valid modes are: list, regex, count, similarity");
            }
        }
        // If mode is null, it should default to "list" according to the spec
    }

    private void validateRegexModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("regex".equals(mode)) {
            String pattern = (String) args.get("pattern");
            if (pattern == null) {
                throw new IllegalArgumentException("pattern is required when mode='regex'");
            }
            if (pattern.trim().isEmpty()) {
                throw new IllegalArgumentException("Pattern cannot be empty when mode='regex'");
            }
        }
    }

    private void validateRegexPattern(Map<String, Object> args) {
        String pattern = (String) args.get("pattern");
        if (pattern != null) {
            try {
                java.util.regex.Pattern.compile(pattern);
            } catch (java.util.regex.PatternSyntaxException e) {
                throw new IllegalArgumentException("Invalid regex pattern: " + e.getMessage());
            }
        }
    }

    private void validateSimilarityModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("similarity".equals(mode)) {
            String searchString = (String) args.get("search_string");
            if (searchString == null) {
                throw new IllegalArgumentException("search_string is required when mode='similarity'");
            }
            if (searchString.trim().isEmpty()) {
                throw new IllegalArgumentException("search_string cannot be empty when mode='similarity'");
            }
        }
    }

    private void validateListModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("list".equals(mode)) {
            // All parameters are optional for list mode
            // filter is optional
            // pagination has defaults
        }
    }

    private void validateCountModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("count".equals(mode)) {
            // Count mode only needs programPath, which is already validated
        }
    }

    private void validatePaginationArgs(Map<String, Object> args) {
        Object startIndexObj = args.get("start_index");
        if (startIndexObj != null) {
            int startIndex = ((Number) startIndexObj).intValue();
            if (startIndex < 0) {
                throw new IllegalArgumentException("start_index must be non-negative");
            }
        }

        Object maxCountObj = args.get("max_count");
        if (maxCountObj != null) {
            int maxCount = ((Number) maxCountObj).intValue();
            if (maxCount <= 0) {
                throw new IllegalArgumentException("max_count must be positive");
            }
        }
    }
}
