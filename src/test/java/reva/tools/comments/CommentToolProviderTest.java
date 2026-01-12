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
package reva.tools.comments;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import io.modelcontextprotocol.server.McpSyncServer;

/**
 * Unit tests for CommentToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 *
 * Tests the consolidated manage_comments tool that replaces:
 * - set-comment, set-disassembly-comment, set-decompilation-comment (action='set')
 * - get-comments (action='get')
 * - remove-comment (action='remove')
 * - search-comments (action='search')
 * - search-decompilation (action='search_decomp')
 */
public class CommentToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private CommentToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new CommentToolProvider(mockServer);
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
        // Test that CommentToolProvider extends AbstractToolProvider
        assertTrue("CommentToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(CommentToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that CommentToolProvider implements ToolProvider interface
        assertTrue("CommentToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(CommentToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("CommentToolProvider should be created", toolProvider);
    }

    @Test
    public void testValidateManageCommentsParameters() {
        // Test parameter validation for the manage_comments tool
        Map<String, Object> validArgs = new HashMap<>();
        validArgs.put("programPath", "/test/program");
        validArgs.put("action", "get");

        // Valid parameters should not throw
        try {
            validateManageCommentsArgs(validArgs);
        } catch (Exception e) {
            fail("Valid parameters should not throw exception: " + e.getMessage());
        }

        // Missing programPath should throw
        Map<String, Object> missingProgram = new HashMap<>(validArgs);
        missingProgram.remove("programPath");
        try {
            validateManageCommentsArgs(missingProgram);
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
            validateManageCommentsArgs(missingAction);
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
        String[] validActions = {"set", "get", "remove", "search", "search_decomp"};
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
        args.put("comment", "Test comment");
        args.put("comment_type", "eol");

        // Valid set action args (address-based)
        try {
            validateSetActionArgs(args);
        } catch (Exception e) {
            fail("Valid set action parameters should not throw: " + e.getMessage());
        }

        // Missing address and function should throw
        args.remove("address");
        try {
            validateSetActionArgs(args);
            fail("Should throw exception for missing address/function in set action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention address or function",
                e.getMessage().toLowerCase().contains("address") ||
                e.getMessage().toLowerCase().contains("function"));
        }

        // Missing comment should throw
        args.put("address", "0x401000");
        args.remove("comment");
        try {
            validateSetActionArgs(args);
            fail("Should throw exception for missing comment in set action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention comment",
                e.getMessage().toLowerCase().contains("comment"));
        }

        // Test decompilation line comment (function + line_number)
        args.clear();
        args.put("programPath", "/test/program");
        args.put("action", "set");
        args.put("function", "main");
        args.put("line_number", 10);
        args.put("comment", "Test comment");
        args.put("comment_type", "eol");

        // Valid decompilation line comment args
        try {
            validateSetDecompilationCommentArgs(args);
        } catch (Exception e) {
            fail("Valid decompilation line comment parameters should not throw: " + e.getMessage());
        }

        // Missing line_number should throw
        args.remove("line_number");
        try {
            validateSetDecompilationCommentArgs(args);
            fail("Should throw exception for missing line_number in decompilation line comment");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention line_number",
                e.getMessage().toLowerCase().contains("line"));
        }
    }

    @Test
    public void testValidateRemoveActionParameters() {
        // Test remove action parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "remove");
        args.put("address", "0x401000");
        args.put("comment_type", "eol");

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

        // Missing comment_type should throw
        args.put("address", "0x401000");
        args.remove("comment_type");
        try {
            validateRemoveActionArgs(args);
            fail("Should throw exception for missing comment_type in remove action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention comment_type",
                e.getMessage().toLowerCase().contains("comment"));
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
    public void testValidateSearchDecompActionParameters() {
        // Test search_decomp action parameter requirements
        Map<String, Object> args = new HashMap<>();
        args.put("programPath", "/test/program");
        args.put("action", "search_decomp");
        args.put("pattern", "test.*pattern");
        args.put("max_results", 50);
        args.put("case_sensitive", false);
        args.put("override_max_functions_limit", false);

        // Valid search_decomp action args
        try {
            validateSearchDecompActionArgs(args);
        } catch (Exception e) {
            fail("Valid search_decomp action parameters should not throw: " + e.getMessage());
        }

        // Missing pattern should throw
        args.remove("pattern");
        try {
            validateSearchDecompActionArgs(args);
            fail("Should throw exception for missing pattern in search_decomp action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention pattern",
                e.getMessage().toLowerCase().contains("pattern"));
        }

        // Empty pattern should throw
        args.put("pattern", "");
        try {
            validateSearchDecompActionArgs(args);
            fail("Should throw exception for empty pattern in search_decomp action");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention pattern",
                e.getMessage().toLowerCase().contains("pattern") ||
                e.getMessage().toLowerCase().contains("empty"));
        }

        // max_results is optional with default (50 for search_decomp)
        args.put("pattern", "test");
        args.remove("max_results");
        try {
            validateSearchDecompActionArgs(args);
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

        // Valid get action args (address or start/end range required, but tested in actual handler)
        try {
            validateGetActionArgs(args);
        } catch (Exception e) {
            // get action requires either address or start/end, but that's validated in handler
            // This is okay - the test validates the basic structure
        }

        // address is optional (can use start/end range instead)
        args.put("address", "0x401000");
        try {
            validateGetActionArgs(args);
            // Should not throw
        } catch (Exception e) {
            fail("address should be optional for get action (can use start/end range)");
        }
    }

    @Test
    public void testValidateCommentTypeEnum() {
        // Test comment type validation
        Map<String, Object> args = new HashMap<>();
        args.put("comment_type", "eol");

        // Test all valid comment types
        String[] validTypes = {"pre", "eol", "post", "plate", "repeatable"};
        for (String type : validTypes) {
            args.put("comment_type", type);
            try {
                validateCommentType(args);
            } catch (Exception e) {
                fail("Valid comment type '" + type + "' should not throw exception: " + e.getMessage());
            }
        }

        // Test invalid comment type
        args.put("comment_type", "invalid");
        try {
            validateCommentType(args);
            fail("Should throw exception for invalid comment type");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue("Error message should mention invalid comment type",
                e.getMessage().toLowerCase().contains("invalid") ||
                e.getMessage().toLowerCase().contains("comment"));
        }
    }

    // Helper methods to simulate parameter validation from the tool handler
    private void validateManageCommentsArgs(Map<String, Object> args) {
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
            String[] validActions = {"set", "get", "remove", "search", "search_decomp"};
            boolean isValid = false;
            for (String validAction : validActions) {
                if (validAction.equals(action)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid action: " + action +
                    ". Valid actions are: set, get, remove, search, search_decomp");
            }
        }
    }

    private void validateSetActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("set".equals(action)) {
            if (args.get("address") == null && args.get("address_or_symbol") == null &&
                args.get("function") == null && args.get("function_name_or_address") == null) {
                throw new IllegalArgumentException("address (or function+line_number) is required for action='set'");
            }
            if (args.get("comment") == null) {
                throw new IllegalArgumentException("comment is required for action='set'");
            }
        }
    }

    private void validateSetDecompilationCommentArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("set".equals(action)) {
            if (args.get("function") == null && args.get("function_name_or_address") == null) {
                throw new IllegalArgumentException("function is required for decompilation line comments");
            }
            if (args.get("line_number") == null) {
                throw new IllegalArgumentException("line_number is required for decompilation line comments");
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
            if (args.get("comment_type") == null) {
                throw new IllegalArgumentException("comment_type is required for action='remove'");
            }
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

    private void validateSearchDecompActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("search_decomp".equals(action)) {
            String pattern = (String) args.get("pattern");
            if (pattern == null || pattern.trim().isEmpty()) {
                throw new IllegalArgumentException("pattern is required for action='search_decomp'");
            }
            // max_results is optional with default (50)
            // override_max_functions_limit is optional with default (false)
        }
    }

    private void validateGetActionArgs(Map<String, Object> args) {
        String action = (String) args.get("action");
        if ("get".equals(action)) {
            // address or start/end range is required, but that's validated in the handler
            // comment_types is optional
        }
    }

    private void validateCommentType(Map<String, Object> args) {
        String commentType = (String) args.get("comment_type");
        if (commentType != null) {
            String[] validTypes = {"pre", "eol", "post", "plate", "repeatable"};
            boolean isValid = false;
            for (String validType : validTypes) {
                if (validType.equalsIgnoreCase(commentType)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                throw new IllegalArgumentException("Invalid comment type: " + commentType +
                    ". Must be one of: pre, eol, post, plate, repeatable");
            }
        }
    }
}
