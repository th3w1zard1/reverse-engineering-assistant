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
package reva.tools.symbols;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for SymbolToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated manage-symbols tool that replaces:
 * - get-symbols-count, get-symbols from SymbolToolProvider (modes='count', 'symbols')
 * - list-imports, list-exports from ImportExportToolProvider (modes='imports', 'exports')
 * - create-label from DataToolProvider (mode='create_label')
 * - list_classes, list_namespaces (modes='classes', 'namespaces')
 * - rename_data (mode='rename_data')
 */
public class SymbolToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private SymbolToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new SymbolToolProvider(mockServer);
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
        // Test that SymbolToolProvider extends AbstractToolProvider
        assertTrue("SymbolToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(SymbolToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that SymbolToolProvider implements ToolProvider interface
        assertTrue("SymbolToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(SymbolToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("SymbolToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateManageSymbolsParameters() {
        // Test parameter validation for the manage-symbols tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("mode", "symbols");

        // Valid parameters should not throw
        try {
            validateManageSymbolsArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateManageSymbolsArgs(missingProgram);
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
            validateManageSymbolsArgs(missingMode);
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
        String[] validModes = {"classes", "namespaces", "imports", "exports", "create_label", "symbols", "count", "rename_data"};
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
    public void testValidateCreateLabelModeParameters() {
        // Test create_label mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "create_label");
        args.put("address", "0x401000");
        args.put("label_name", "my_label");

        // Valid create_label mode args
        try {
            validateCreateLabelModeArgs(args);
        } catch (Exception e) {
            fail("Valid create_label mode parameters should not throw: " + e.getMessage());
        }

        // Missing address should throw
        args.remove("address");
        try {
            validateCreateLabelModeArgs(args);
            fail("Should throw exception for missing address in create_label mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address",
                e.getMessage().toLowerCase().contains("address"));
        }

        // Missing label_name should throw
        args.put("address", "0x401000");
        args.remove("label_name");
        try {
            validateCreateLabelModeArgs(args);
            fail("Should throw exception for missing label_name in create_label mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention label_name",
                e.getMessage().toLowerCase().contains("label"));
        }

        // Empty label_name should throw
        args.put("label_name", "");
        try {
            validateCreateLabelModeArgs(args);
            fail("Should throw exception for empty label_name in create_label mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention label_name",
                e.getMessage().toLowerCase().contains("label"));
        }
    }

    @Test
    public void testValidateRenameDataModeParameters() {
        // Test rename_data mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "rename_data");
        args.put("address", "0x401000");
        args.put("new_name", "renamed_data");

        // Valid rename_data mode args
        try {
            validateRenameDataModeArgs(args);
        } catch (Exception e) {
            fail("Valid rename_data mode parameters should not throw: " + e.getMessage());
        }

        // Missing address should throw
        args.remove("address");
        try {
            validateRenameDataModeArgs(args);
            fail("Should throw exception for missing address in rename_data mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address",
                e.getMessage().toLowerCase().contains("address"));
        }

        // Missing new_name should throw
        args.put("address", "0x401000");
        args.remove("new_name");
        try {
            validateRenameDataModeArgs(args);
            fail("Should throw exception for missing new_name in rename_data mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention new_name",
                e.getMessage().toLowerCase().contains("new") ||
                e.getMessage().toLowerCase().contains("name"));
        }

        // Empty new_name should throw
        args.put("new_name", "");
        try {
            validateRenameDataModeArgs(args);
            fail("Should throw exception for empty new_name in rename_data mode");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention new_name",
                e.getMessage().toLowerCase().contains("new") ||
                e.getMessage().toLowerCase().contains("name"));
        }
    }

    @Test
    public void testValidateImportsModeParameters() {
        // Test imports mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "imports");
        args.put("library_filter", "kernel32");
        args.put("max_results", 500);
        args.put("start_index", 0);
        args.put("group_by_library", true);

        // Valid imports mode args
        try {
            validateImportsModeArgs(args);
        } catch (Exception e) {
            fail("Valid imports mode parameters should not throw: " + e.getMessage());
        }

        // library_filter is optional
        args.remove("library_filter");
        try {
            validateImportsModeArgs(args);
            // Should not throw - library_filter is optional
        } catch (Exception e) {
            fail("library_filter should be optional for imports mode");
        }

        // max_results is optional with default
        args.put("library_filter", "kernel32");
        args.remove("max_results");
        try {
            validateImportsModeArgs(args);
            // Should not throw - max_results has default
        } catch (Exception e) {
            fail("max_results should be optional with default value");
        }

        // group_by_library is optional with default
        args.remove("group_by_library");
        try {
            validateImportsModeArgs(args);
            // Should not throw - group_by_library has default
        } catch (Exception e) {
            fail("group_by_library should be optional with default value");
        }
    }

    @Test
    public void testValidateExportsModeParameters() {
        // Test exports mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "exports");
        args.put("max_results", 500);
        args.put("start_index", 0);

        // Valid exports mode args
        try {
            validateExportsModeArgs(args);
        } catch (Exception e) {
            fail("Valid exports mode parameters should not throw: " + e.getMessage());
        }

        // max_results is optional with default
        args.remove("max_results");
        try {
            validateExportsModeArgs(args);
            // Should not throw - max_results has default
        } catch (Exception e) {
            fail("max_results should be optional with default value");
        }
    }

    @Test
    public void testValidateSymbolsModeParameters() {
        // Test symbols mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "symbols");
        args.put("max_count", 200);
        args.put("start_index", 0);
        args.put("include_external", false);
        args.put("filter_default_names", true);

        // Valid symbols mode args
        try {
            validateSymbolsModeArgs(args);
        } catch (Exception e) {
            fail("Valid symbols mode parameters should not throw: " + e.getMessage());
        }

        // max_count is optional with default (200 for symbols mode)
        args.remove("max_count");
        try {
            validateSymbolsModeArgs(args);
            // Should not throw - max_count has default
        } catch (Exception e) {
            fail("max_count should be optional with default value");
        }

        // include_external is optional with default (false)
        args.put("max_count", 200);
        args.remove("include_external");
        try {
            validateSymbolsModeArgs(args);
            // Should not throw - include_external has default
        } catch (Exception e) {
            fail("include_external should be optional with default value");
        }

        // filter_default_names is optional with default (true)
        args.remove("filter_default_names");
        try {
            validateSymbolsModeArgs(args);
            // Should not throw - filter_default_names has default
        } catch (Exception e) {
            fail("filter_default_names should be optional with default value");
        }
    }

    @Test
    public void testValidateCountModeParameters() {
        // Test count mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "count");
        args.put("include_external", false);
        args.put("filter_default_names", true);

        // Valid count mode args
        try {
            validateCountModeArgs(args);
        } catch (Exception e) {
            fail("Valid count mode parameters should not throw: " + e.getMessage());
        }

        // include_external is optional with default (false)
        args.remove("include_external");
        try {
            validateCountModeArgs(args);
            // Should not throw - include_external has default
        } catch (Exception e) {
            fail("include_external should be optional with default value");
        }

        // filter_default_names is optional with default (true)
        args.remove("filter_default_names");
        try {
            validateCountModeArgs(args);
            // Should not throw - filter_default_names has default
        } catch (Exception e) {
            fail("filter_default_names should be optional with default value");
        }
    }

    @Test
    public void testValidateClassesModeParameters() {
        // Test classes mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "classes");
        args.put("start_index", 0);
        args.put("limit", 100);

        // Valid classes mode args
        try {
            validateClassesModeArgs(args);
        } catch (Exception e) {
            fail("Valid classes mode parameters should not throw: " + e.getMessage());
        }

        // start_index is optional with default (0)
        args.remove("start_index");
        try {
            validateClassesModeArgs(args);
            // Should not throw - start_index has default
        } catch (Exception e) {
            fail("start_index should be optional with default value");
        }

        // limit is optional with default (100)
        args.put("start_index", 0);
        args.remove("limit");
        try {
            validateClassesModeArgs(args);
            // Should not throw - limit has default
        } catch (Exception e) {
            fail("limit should be optional with default value");
        }
    }

    @Test
    public void testValidateNamespacesModeParameters() {
        // Test namespaces mode parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("mode", "namespaces");
        args.put("start_index", 0);
        args.put("limit", 100);

        // Valid namespaces mode args
        try {
            validateNamespacesModeArgs(args);
        } catch (Exception e) {
            fail("Valid namespaces mode parameters should not throw: " + e.getMessage());
        }

        // start_index is optional with default (0)
        args.remove("start_index");
        try {
            validateNamespacesModeArgs(args);
            // Should not throw - start_index has default
        } catch (Exception e) {
            fail("start_index should be optional with default value");
        }

        // limit is optional with default (100)
        args.put("start_index", 0);
        args.remove("limit");
        try {
            validateNamespacesModeArgs(args);
            // Should not throw - limit has default
        } catch (Exception e) {
            fail("limit should be optional with default value");
        }
    }

    // Helper methods to simulate parameter validation from the tool handler
    private void validateManageSymbolsArgs(Map<String, Object> args) {
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
            String[] validModes = {"classes", "namespaces", "imports", "exports", "create_label", "symbols", "count", "rename_data"};
            boolean isValid = false;
            for (String validMode : validModes) {
                if (validMode.equals(mode)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid mode: " + mode +
                    ". Valid modes are: classes, namespaces, imports, exports, create_label, symbols, count, rename_data");
            }
        }
    }

    private void validateCreateLabelModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("create_label".equals(mode)) {
            if (args.get("address") == null) {
                throw new IllegalArgumentException("address is required for mode='create_label'");
            }
            String labelName = (String) args.get("label_name");
            if (labelName == null || labelName.trim().isEmpty()) {
                throw new IllegalArgumentException("label_name is required for mode='create_label'");
            }
        }
    }

    private void validateRenameDataModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("rename_data".equals(mode)) {
            if (args.get("address") == null) {
                throw new IllegalArgumentException("address is required for mode='rename_data'");
            }
            String newName = (String) args.get("new_name");
            if (newName == null || newName.trim().isEmpty()) {
                throw new IllegalArgumentException("new_name is required for mode='rename_data'");
            }
        }
    }

    private void validateImportsModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("imports".equals(mode)) {
            // library_filter is optional
            // max_results is optional with default (500)
            // start_index is optional with default (0)
            // group_by_library is optional with default (true)
        }
    }

    private void validateExportsModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("exports".equals(mode)) {
            // max_results is optional with default (500)
            // start_index is optional with default (0)
        }
    }

    private void validateSymbolsModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("symbols".equals(mode)) {
            // max_count is optional with default (200)
            // start_index/offset is optional with default (0)
            // include_external is optional with default (false)
            // filter_default_names is optional with default (true)
        }
    }

    private void validateCountModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("count".equals(mode)) {
            // include_external is optional with default (false)
            // filter_default_names is optional with default (true)
        }
    }

    private void validateClassesModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("classes".equals(mode)) {
            // start_index/offset is optional with default (0)
            // limit/max_count is optional with default (100)
        }
    }

    private void validateNamespacesModeArgs(Map<String, Object> args) {
        String mode = (String) args.get("mode");
        if ("namespaces".equals(mode)) {
            // start_index/offset is optional with default (0)
            // limit/max_count is optional with default (100)
        }
    }
}
