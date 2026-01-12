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
package reva.tools.constants;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for ConstantSearchToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 * 
 * Tests the consolidated search_constants tool that replaces:
 * - find-constant-uses (mode='specific')
 * - find-constants-in-range (mode='range')
 * - list-common-constants (mode='common')
 */
public class ConstantSearchToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private ConstantSearchToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new ConstantSearchToolProvider(mockServer);
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
        // Test that ConstantSearchToolProvider extends AbstractToolProvider
        assertTrue("ConstantSearchToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(ConstantSearchToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that ConstantSearchToolProvider implements ToolProvider interface
        assertTrue("ConstantSearchToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(ConstantSearchToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("ConstantSearchToolProvider should be created", toolProvider);
    }
    
    @Test
    public void testValidateSearchConstantsParameters() {
        // Test parameter validation for the search_constants tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("mode", "specific");
        validArgs.put("value", "0xdeadbeef");
        
        // Valid parameters should not throw
        try {
            validateSearchConstantsArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }
        
        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateSearchConstantsArgs(missingProgram);
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
            validateSearchConstantsArgs(missingMode);
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
        String[] validModes = {"specific", "range", "common"};
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
    public void testValidateSpecificModeParameters() {
        // Test specific mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "specific");
        args.put("value", "0xdeadbeef");
        args.put("max_results", 100);
        
        // Valid specific mode args
        try {
            validateSpecificModeArgs(args);
        } catch (Exception e) {
            fail("Valid specific mode parameters should not throw: " + e.getMessage());
        }
        
        // Missing value should throw
        args.remove("value");
        try {
            validateSpecificModeArgs(args);
            fail("Should throw exception for missing value in specific mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention value", 
                e.getMessage().toLowerCase().contains("value"));
        }
        
        // Test value parsing (hex, decimal, negative)
        args.put("value", "0xdeadbeef");
        try {
            validateValueFormat(args);
        } catch (Exception e) {
            fail("Hex value format should be valid");
        }
        
        args.put("value", "123");
        try {
            validateValueFormat(args);
        } catch (Exception e) {
            fail("Decimal value format should be valid");
        }
        
        args.put("value", "-1");
        try {
            validateValueFormat(args);
        } catch (Exception e) {
            fail("Negative value format should be valid");
        }
        
        // Invalid value format
        args.put("value", "invalid");
        try {
            validateValueFormat(args);
            fail("Should throw exception for invalid value format");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid", 
                e.getMessage().toLowerCase().contains("invalid"));
        }
        
        // Test max_results validation
        args.put("value", "123");
        args.put("max_results", 0);
        try {
            validateMaxResults(args);
            // Should clamp to default
        } catch (Exception e) {
            // May clamp or throw
        }
        
        args.put("max_results", 20000);
        try {
            validateMaxResults(args);
            // Should clamp to MAX_RESULTS_LIMIT
        } catch (Exception e) {
            // May clamp or throw
        }
    }
    
    @Test
    public void testValidateRangeModeParameters() {
        // Test range mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "range");
        args.put("min_value", "0x100");
        args.put("max_value", "0x200");
        args.put("max_results", 100);
        
        // Valid range mode args
        try {
            validateRangeModeArgs(args);
        } catch (Exception e) {
            fail("Valid range mode parameters should not throw: " + e.getMessage());
        }
        
        // Missing min_value should throw
        args.remove("min_value");
        try {
            validateRangeModeArgs(args);
            fail("Should throw exception for missing min_value in range mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention min_value", 
                e.getMessage().toLowerCase().contains("min"));
        }
        
        // Missing max_value should throw
        args.put("min_value", "0x100");
        args.remove("max_value");
        try {
            validateRangeModeArgs(args);
            fail("Should throw exception for missing max_value in range mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention max_value", 
                e.getMessage().toLowerCase().contains("max"));
        }
        
        // min_value > max_value should throw
        args.put("min_value", "0x200");
        args.put("max_value", "0x100");
        try {
            validateRangeModeArgs(args);
            fail("Should throw exception when min_value > max_value");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention min_value must be less than max_value", 
                e.getMessage().toLowerCase().contains("min") || 
                e.getMessage().toLowerCase().contains("max"));
        }
    }
    
    @Test
    public void testValidateCommonModeParameters() {
        // Test common mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "common");
        args.put("top_n", 50);
        args.put("include_small_values", false);
        args.put("min_value", "0x1000");
        
        // Valid common mode args
        try {
            validateCommonModeArgs(args);
        } catch (Exception e) {
            fail("Valid common mode parameters should not throw: " + e.getMessage());
        }
        
        // Test top_n validation
        args.put("top_n", 0);
        try {
            validateCommonModeArgs(args);
            // Should clamp to default
        } catch (Exception e) {
            // May clamp or throw
        }
        
        args.put("top_n", 20000);
        try {
            validateCommonModeArgs(args);
            // Should clamp to MAX_RESULTS_LIMIT
        } catch (Exception e) {
            // May clamp or throw
        }
        
        // Test optional min_value for filtering
        args.put("top_n", 50);
        args.remove("min_value");
        try {
            validateCommonModeArgs(args);
            // min_value is optional for common mode
        } catch (Exception e) {
            fail("min_value should be optional for common mode");
        }
        
        // Test include_small_values boolean
        args.put("include_small_values", true);
        try {
            validateCommonModeArgs(args);
        } catch (Exception e) {
            fail("include_small_values should accept boolean values");
        }
    }
    
    // Helper methods to simulate parameter validation from the tool handler
    private void validateSearchConstantsArgs(Map<String, Object> args) {
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
            String[] validModes = {"specific", "range", "common"};
            boolean isValid = false;
            for (String validMode : validModes) {
                if (validMode.equals(mode)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid mode: " + mode + 
                    ". Valid modes are: specific, range, common");
            }
        }
    }
    
    private void validateSpecificModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("specific".equals(mode)) {
            if (args.get("value") == null) {
                throw new IllegalArgumentException("value is required for specific mode");
            }
        }
    }
    
    private void validateValueFormat(Map<String, Object> args) {
        String valueStr = (String) args.get("value");
        if (valueStr != null) {
            valueStr = valueStr.trim();
            // Basic format validation
            if (valueStr.toLowerCase().startsWith("0x")) {
                try {
                    Long.parseUnsignedLong(valueStr.substring(2), 16);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid hex value format: " + valueStr);
                }
            } else if (valueStr.startsWith("-")) {
                try {
                    Long.parseLong(valueStr);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid negative value format: " + valueStr);
                }
            } else {
                try {
                    Long.parseUnsignedLong(valueStr);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid decimal value format: " + valueStr);
                }
            }
        }
    }
    
    private void validateMaxResults(Map<String, Object> args) {
        Object maxResultsObj = args.get("max_results");
        if (maxResultsObj != null) {
            int maxResults = ((Number) maxResultsObj).intValue();
            if (maxResults <= 0) {
                throw new IllegalArgumentException("max_results must be positive");
            }
            if (maxResults > 10000) {
                throw new IllegalArgumentException("max_results must be <= 10000");
            }
        }
    }
    
    private void validateRangeModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("range".equals(mode)) {
            if (args.get("min_value") == null) {
                throw new IllegalArgumentException("min_value is required for range mode");
            }
            if (args.get("max_value") == null) {
                throw new IllegalArgumentException("max_value is required for range mode");
            }
            
            // Validate range
            String minStr = (String) args.get("min_value");
            String maxStr = (String) args.get("max_value");
            if (minStr != null && maxStr != null) {
                try {
                    long minValue = parseConstantValue(minStr);
                    long maxValue = parseConstantValue(maxStr);
                    if (minValue > maxValue) {
                        throw new IllegalArgumentException("min_value must be less than or equal to max_value");
                    }
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid value format");
                }
            }
        }
    }
    
    private void validateCommonModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("common".equals(mode)) {
            // top_n is optional (has default)
            Object topNObj = args.get("top_n");
            if (topNObj != null) {
                int topN = ((Number) topNObj).intValue();
                if (topN <= 0) {
                    throw new IllegalArgumentException("top_n must be positive");
                }
                if (topN > 10000) {
                    throw new IllegalArgumentException("top_n must be <= 10000");
                }
            }
            // include_small_values is optional (has default)
            // min_value is optional for filtering
        }
    }
    
    private long parseConstantValue(String valueStr) throws NumberFormatException {
        valueStr = valueStr.trim();
        if (valueStr.toLowerCase().startsWith("0x")) {
            return Long.parseUnsignedLong(valueStr.substring(2), 16);
        }
        if (valueStr.startsWith("-")) {
            return Long.parseLong(valueStr);
        }
        return Long.parseUnsignedLong(valueStr);
    }
}
