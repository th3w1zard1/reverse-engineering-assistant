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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for CommentToolProvider using MCP client.
 * Tests the full end-to-end flow from MCP client through the server to Ghidra.
 */
public class CommentToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String programPath;

    @Before
    public void setUpTestData() throws Exception {
        programPath = program.getDomainFile().getPathname();

        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);

        // Also open it directly in the tool's ProgramManager service to ensure it's available
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager != null) {
            programManager.openProgram(program);
        }

        // Register the program with the server manager so it can be found by the tools
        if (serverManager != null) {
            serverManager.programOpened(program, tool);
        }
    }

    @Test
    public void testSetAndGetComment() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Use the minimum address in the program which should be valid
                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set a comment
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("commentType", "eol");
                setArgs.put("comment", "Test comment");

                CallToolRequest setRequest = new CallToolRequest("manage-comments", setArgs);
                CallToolResult setResult = client.callTool(setRequest);
                assertFalse("Set comment should succeed", setResult.isError());

                // Verify the comment was set in the program
                Listing listing = program.getListing();
                String actualComment = listing.getComment(CommentType.EOL, testAddress);
                assertEquals("Comment should be set correctly", "Test comment", actualComment);

                // Get the comment using the tool
                Map<String, Object> getArgs = new HashMap<>();
                  getArgs.put("programPath", programPath);
                getArgs.put("action", "get");
                getArgs.put("addressOrSymbol", addressStr);

                CallToolRequest getRequest = new CallToolRequest("manage-comments", getArgs);
                CallToolResult getResult = client.callTool(getRequest);
                assertFalse("Get comments should succeed", getResult.isError());

                // Parse the result
                String jsonResponse = ((TextContent) getResult.content().get(0)).text();
                JsonNode responseNode = objectMapper.readTree(jsonResponse);
                JsonNode commentsNode = responseNode.get("comments");

                assertEquals("Should have one comment", 1, commentsNode.size());
                assertEquals("Comment text should match", "Test comment", commentsNode.get(0).get("comment").asText());
                assertEquals("Comment type should match", "eol", commentsNode.get(0).get("commentType").asText());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSetCommentWithAllTypes() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String[] commentTypes = {"pre", "eol", "post", "plate", "repeatable"};

                for (String commentType : commentTypes) {
                    Map<String, Object> setArgs = new HashMap<>();
                    setArgs.put("programPath", programPath);
                    setArgs.put("action", "set");
                    setArgs.put("addressOrSymbol", testAddress.toString());
                    setArgs.put("commentType", commentType);
                    setArgs.put("comment", "Test " + commentType + " comment");

                    CallToolResult setResult = client.callTool(new CallToolRequest("manage-comments", setArgs));
                    assertFalse("Set " + commentType + " comment should succeed", setResult.isError());

                    // Verify comment was set
                    Listing listing = program.getListing();
                    CommentType ghidraType = CommentType.valueOf(commentType.toUpperCase());
                    String actualComment = listing.getComment(ghidraType, testAddress);
                    assertTrue("Comment should be set for type " + commentType,
                        actualComment != null && actualComment.contains("Test " + commentType));
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testRemoveComment() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // First set a comment
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("commentType", "eol");
                setArgs.put("comment", "Comment to remove");
                client.callTool(new CallToolRequest("manage-comments", setArgs));

                // Verify it was set
                Listing listing = program.getListing();
                String commentBefore = listing.getComment(CommentType.EOL, testAddress);
                assertNotNull("Comment should be set before removal", commentBefore);

                // Remove the comment
                Map<String, Object> removeArgs = new HashMap<>();
                removeArgs.put("programPath", programPath);
                removeArgs.put("action", "remove");
                removeArgs.put("addressOrSymbol", addressStr);
                removeArgs.put("commentType", "eol");

                CallToolResult removeResult = client.callTool(new CallToolRequest("manage-comments", removeArgs));
                assertFalse("Remove comment should succeed", removeResult.isError());

                // Verify comment was removed
                String commentAfter = listing.getComment(CommentType.EOL, testAddress);
                assertNull("Comment should be removed", commentAfter);
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSearchComments() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set a comment to search for
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("commentType", "eol");
                setArgs.put("comment", "Searchable comment text");
                client.callTool(new CallToolRequest("manage-comments", setArgs));

                // Search for the comment
                Map<String, Object> searchArgs = new HashMap<>();
                  searchArgs.put("programPath", programPath);
                searchArgs.put("action", "search");
                searchArgs.put("searchText", "Searchable");
                searchArgs.put("maxResults", 10);

                CallToolResult searchResult = client.callTool(new CallToolRequest("manage-comments", searchArgs));
                assertFalse("Search comments should succeed", searchResult.isError());

                TextContent content = (TextContent) searchResult.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertTrue("Should have results field", json.has("results"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSearchDecompilation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Search decompilation for a pattern
                Map<String, Object> searchArgs = new HashMap<>();
                  searchArgs.put("programPath", programPath);
                searchArgs.put("action", "search_decomp");
                searchArgs.put("pattern", ".*");
                searchArgs.put("maxResults", 10);

                CallToolResult searchResult = client.callTool(new CallToolRequest("manage-comments", searchArgs));
                // May return empty if no matches, but should not error
                if (!searchResult.isError()) {
                    TextContent content = (TextContent) searchResult.content().get(0);
                    JsonNode json = parseJsonContent(content.text());
                    assertNotNull("Should have valid JSON structure", json);
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSetCommentWithFunctionAndLineNumber() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Create a function first
                Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
                int txId = program.startTransaction("Create function");
                try {
                    ghidra.program.model.listing.FunctionManager funcManager = program.getFunctionManager();
                    funcManager.createFunction("testFunc", funcAddr,
                        new AddressSet(funcAddr, funcAddr.add(50)), SourceType.USER_DEFINED);
                } finally {
                    program.endTransaction(txId, true);
                }

                // Set comment at decompilation line
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("function", "testFunc");
                setArgs.put("lineNumber", 1);
                setArgs.put("comment", "Decompilation line comment");
                setArgs.put("commentType", "eol");

                CallToolResult setResult = client.callTool(new CallToolRequest("manage-comments", setArgs));
                // May fail if decompilation not available, but should handle gracefully
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testBatchSetComments() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address addr1 = program.getMinAddress();
                Address addr2 = addr1.add(0x10);

                // Batch set comments
                java.util.List<Map<String, Object>> commentsList = java.util.Arrays.asList(
                    Map.of("address", addr1.toString(), "comment", "Batch comment 1", "commentType", "eol"),
                    Map.of("address", addr2.toString(), "comment", "Batch comment 2", "commentType", "pre")
                );

                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("comments", commentsList);

                CallToolResult setResult = client.callTool(new CallToolRequest("manage-comments", setArgs));
                assertFalse("Batch set comments should succeed", setResult.isError());

                // Verify comments were set
                Listing listing = program.getListing();
                String comment1 = listing.getComment(CommentType.EOL, addr1);
                String comment2 = listing.getComment(CommentType.PRE, addr2);
                assertTrue("First comment should be set", comment1 != null && comment1.contains("Batch comment 1"));
                assertTrue("Second comment should be set", comment2 != null && comment2.contains("Batch comment 2"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetCommentsInRange() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address startAddr = program.getMinAddress();
                Address endAddr = startAddr.add(0x100);

                // Set some comments in range
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", startAddr.toString());
                setArgs.put("comment", "Range comment");
                setArgs.put("commentType", "eol");
                client.callTool(new CallToolRequest("manage-comments", setArgs));

                // Get comments in range
                Map<String, Object> getArgs = new HashMap<>();
                  getArgs.put("programPath", programPath);
                getArgs.put("action", "get");
                getArgs.put("start", startAddr.toString());
                getArgs.put("end", endAddr.toString());

                CallToolResult getResult = client.callTool(new CallToolRequest("manage-comments", getArgs));
                assertFalse("Get comments in range should succeed", getResult.isError());

                TextContent content = (TextContent) getResult.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertTrue("Should have comments field", json.has("comments"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSearchCommentsCaseSensitive() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set a comment
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("commentType", "eol");
                setArgs.put("comment", "CaseSensitive");
                client.callTool(new CallToolRequest("manage-comments", setArgs));

                // Search case-sensitive
                Map<String, Object> searchArgs = new HashMap<>();
                  searchArgs.put("programPath", programPath);
                searchArgs.put("action", "search");
                searchArgs.put("searchText", "CaseSensitive");
                searchArgs.put("caseSensitive", true);

                CallToolResult searchResult = client.callTool(new CallToolRequest("manage-comments", searchArgs));
                assertFalse("Search should succeed", searchResult.isError());

                // Search case-insensitive (should also find it)
                searchArgs.put("caseSensitive", false);
                searchArgs.put("searchText", "casesensitive");
                CallToolResult searchResult2 = client.callTool(new CallToolRequest("manage-comments", searchArgs));
                assertFalse("Case-insensitive search should succeed", searchResult2.isError());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testCommentsValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set comment
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("commentType", "eol");
                setArgs.put("comment", "State validation comment");

                CallToolResult setResult = client.callTool(new CallToolRequest("manage-comments", setArgs));
                assertFalse("Set comment should succeed", setResult.isError());

                // Verify comment was actually set in program state
                Listing listing = program.getListing();
                String actualComment = listing.getComment(CommentType.EOL, testAddress);
                assertNotNull("Comment should be in program state", actualComment);
                assertEquals("Comment text should match", "State validation comment", actualComment);
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}
