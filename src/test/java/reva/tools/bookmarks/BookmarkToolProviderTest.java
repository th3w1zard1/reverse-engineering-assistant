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
package reva.tools.bookmarks;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for BookmarkToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated manage-bookmarks tool that replaces:
 * - set-bookmark (action='set')
 * - get-bookmarks (action='get')
 * - search-bookmarks (action='search')
 * - remove-bookmark (action='remove')
 * - list-bookmark-categories (action='categories')
 */
public class BookmarkToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private BookmarkToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new BookmarkToolProvider(mockServer);
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
        // Test that BookmarkToolProvider extends AbstractToolProvider
        assertTrue("BookmarkToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(BookmarkToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that BookmarkToolProvider implements ToolProvider interface
        assertTrue("BookmarkToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(BookmarkToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("BookmarkToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateManageBookmarksParameters() {
        // Test parameter validation for the manage-bookmarks tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("action", "get");

        // Valid parameters should not throw
        try {
            validateManageBookmarksArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateManageBookmarksArgs(missingProgram);
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
            validateManageBookmarksArgs(missingAction);
            fail("Should throw exception for missing action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention action",
                e.getMessage().toLowerCase().contains("action"));
        }
    }

    @Test
    public void testValidateActionEnum() {
        // Test that all valid actions are accepted
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");

        // Test all valid actions
        String[] validActions = {"set", "get", "search", "remove", "categories"};
        for (String action : validActions) {
            args.put("action", action);
            try {
                validateActionEnum(args);
            } catch (Exception e) {
                fail("Valid action '" + action + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test invalid action
        args.put("action", "invalid");
        try {
            validateActionEnum(args);
            fail("Should throw exception for invalid action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid action",
                e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testValidateSetActionParameters() {
        // Test set action parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "set");
        args.put("address", "0x401000");
        args.put("type", "Note");
        args.put("category", "test");
        args.put("comment", "Test bookmark");

        // Valid set action args
        try {
            validateSetActionArgs(args);
        } catch (Exception e) {
            fail("Valid set action parameters should not throw: " + e.getMessage());
        }

        // Missing address should throw
        args.remove("address");
        try {
            validateSetActionArgs(args);
            fail("Should throw exception for missing address in set action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address",
                e.getMessage().toLowerCase().contains("address"));
        }

        // Missing type should throw
        args.put("address", "0x401000");
        args.remove("type");
        try {
            validateSetActionArgs(args);
            fail("Should throw exception for missing type in set action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention type",
                e.getMessage().toLowerCase().contains("type"));
        }

        // Missing category should throw
        args.put("type", "Note");
        args.remove("category");
        try {
            validateSetActionArgs(args);
            fail("Should throw exception for missing category in set action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention category",
                e.getMessage().toLowerCase().contains("category"));
        }

        // Missing comment should throw
        args.put("category", "test");
        args.remove("comment");
        try {
            validateSetActionArgs(args);
            fail("Should throw exception for missing comment in set action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention comment",
                e.getMessage().toLowerCase().contains("comment"));
        }
    }

    @Test
    public void testValidateRemoveActionParameters() {
        // Test remove action parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "remove");
        args.put("address", "0x401000");
        args.put("type", "Note");
        args.put("category", "test");

        // Valid remove action args
        try {
            validateRemoveActionArgs(args);
        } catch (Exception e) {
            fail("Valid remove action parameters should not throw: " + e.getMessage());
        }

        // Missing address should throw
        args.remove("address");
        try {
            validateRemoveActionArgs(args);
            fail("Should throw exception for missing address in remove action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address",
                e.getMessage().toLowerCase().contains("address"));
        }

        // Missing type should throw
        args.put("address", "0x401000");
        args.remove("type");
        try {
            validateRemoveActionArgs(args);
            fail("Should throw exception for missing type in remove action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention type",
                e.getMessage().toLowerCase().contains("type"));
        }

        // Category is optional for remove action
        args.put("type", "Note");
        args.remove("category");
        try {
            validateRemoveActionArgs(args);
            // Should not throw - category is optional
        } catch (IllegalArgumentException e) {
            fail("Category should be optional for remove action");
        }
    }

    @Test
    public void testValidateSearchActionParameters() {
        // Test search action parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "search");
        args.put("search_text", "test");
        args.put("max_results", 100);

        // Valid search action args
        try {
            validateSearchActionArgs(args);
        } catch (Exception e) {
            fail("Valid search action parameters should not throw: " + e.getMessage());
        }

        // Missing search_text should throw
        args.remove("search_text");
        try {
            validateSearchActionArgs(args);
            fail("Should throw exception for missing search_text in search action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention search_text",
                e.getMessage().toLowerCase().contains("search"));
        }

        // Empty search_text should throw
        args.put("search_text", "");
        try {
            validateSearchActionArgs(args);
            fail("Should throw exception for empty search_text in search action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention search_text",
                e.getMessage().toLowerCase().contains("search"));
        }

        // max_results is optional with default
        args.put("search_text", "test");
        args.remove("max_results");
        try {
            validateSearchActionArgs(args);
            // Should not throw - max_results has default
        } catch (Exception e) {
            fail("max_results should be optional with default value");
        }
    }

    @Test
    public void testValidateGetActionParameters() {
        // Test get action parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "get");

        // Valid get action args (no required parameters beyond action)
        try {
            validateGetActionArgs(args);
        } catch (Exception e) {
            fail("Valid get action parameters should not throw: " + e.getMessage());
        }

        // address is optional for get action
        args.put("address", "0x401000");
        try {
            validateGetActionArgs(args);
            // Should not throw - address is optional
        } catch (Exception e) {
            fail("address should be optional for get action");
        }

        // type and category filters are optional
        args.put("type", "Note");
        args.put("category", "test");
        try {
            validateGetActionArgs(args);
            // Should not throw - filters are optional
        } catch (Exception e) {
            fail("type and category should be optional filters for get action");
        }
    }

    @Test
    public void testValidateCategoriesActionParameters() {
        // Test categories action parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "categories");

        // Valid categories action args (no required parameters beyond action)
        try {
            validateCategoriesActionArgs(args);
        } catch (Exception e) {
            fail("Valid categories action parameters should not throw: " + e.getMessage());
        }

        // type filter is optional for categories action
        args.put("type", "Note");
        try {
            validateCategoriesActionArgs(args);
            // Should not throw - type is optional filter
        } catch (Exception e) {
            fail("type should be optional filter for categories action");
        }
    }

    // Helper methods to simulate parameter validation from the tool handler
    private void validateManageBookmarksArgs(Map<String, Object> args) {
        if (args.get("programPath") == null) {
            throw new IllegalArgumentException("No program path provided");
        }
        if (args.get("action") == null) {
            throw new IllegalArgumentException("No action provided");
        }
    }

    private void validateActionEnum(Map<String, Object> args) {
        String action = (String) args.get("action");
        if (action != null) {
            String[] validActions = {"set", "get", "search", "remove", "categories"};
            boolean isValid = false;
            for (String validAction : validActions) {
                if (validAction.equals(action)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid action: " + action +
                    ". Valid actions are: set, get, search, remove, categories");
            }
        }
    }

    private void validateSetActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("set".equals(action)) {
            if (args.get("address") == null && args.get("address_or_symbol") == null) {
                throw new IllegalArgumentException("address is required for action='set'");
            }
            if (args.get("type") == null) {
                throw new IllegalArgumentException("type is required for action='set'");
            }
            if (args.get("category") == null) {
                throw new IllegalArgumentException("category is required for action='set'");
            }
            if (args.get("comment") == null) {
                throw new IllegalArgumentException("comment is required for action='set'");
            }
        }
    }

    private void validateRemoveActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("remove".equals(action)) {
            if (args.get("address") == null && args.get("address_or_symbol") == null) {
                throw new IllegalArgumentException("address is required for action='remove'");
            }
            if (args.get("type") == null) {
                throw new IllegalArgumentException("type is required for action='remove'");
            }
            // category is optional for remove
        }
    }

    private void validateSearchActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("search".equals(action)) {
            String searchText = (String) args.get("search_text");
            if (searchText == null || searchText.trim().isEmpty()) {
                throw new IllegalArgumentException("search_text is required for action='search'");
            }
            // max_results is optional with default
        }
    }

    private void validateGetActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("get".equals(action)) {
            // address, type, and category are optional filters
        }
    }

    private void validateCategoriesActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("categories".equals(action)) {
            // type is optional filter
        }
    }
}
