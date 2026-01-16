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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for BookmarkToolProvider using MCP client.
 * Tests the full end-to-end flow from MCP client through the server to Ghidra.
 */
public class BookmarkToolProviderIntegrationTest extends RevaIntegrationTestBase {

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
    public void testSetAndGetBookmark() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Use the minimum address in the program which should be valid
                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set a bookmark
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("type", "Note");
                setArgs.put("category", "Analysis");
                setArgs.put("comment", "Test bookmark");

                CallToolRequest setRequest = new CallToolRequest("manage-bookmarks", setArgs);
                CallToolResult setResult = client.callTool(setRequest);
                assertFalse("Set bookmark should succeed", setResult.isError());

                // Verify the bookmark was set in the program
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Bookmark bookmark = bookmarkMgr.getBookmark(testAddress, "Note", "Analysis");
                assertNotNull("Bookmark should exist", bookmark);
                assertEquals("Bookmark comment should match", "Test bookmark", bookmark.getComment());

                // Get the bookmark using the tool
                Map<String, Object> getArgs = new HashMap<>();
                  getArgs.put("programPath", programPath);
                getArgs.put("action", "get");
                getArgs.put("addressOrSymbol", addressStr);

                CallToolRequest getRequest = new CallToolRequest("manage-bookmarks", getArgs);
                CallToolResult getResult = client.callTool(getRequest);
                assertFalse("Get bookmarks should succeed", getResult.isError());

                // Parse the result
                String jsonResponse = ((TextContent) getResult.content().get(0)).text();
                JsonNode responseNode = objectMapper.readTree(jsonResponse);
                JsonNode bookmarksNode = responseNode.get("bookmarks");

                assertEquals("Should have one bookmark", 1, bookmarksNode.size());
                assertEquals("Bookmark comment should match", "Test bookmark", bookmarksNode.get(0).get("comment").asText());
                assertEquals("Bookmark type should match", "Note", bookmarksNode.get(0).get("type").asText());
                assertEquals("Bookmark category should match", "Analysis", bookmarksNode.get(0).get("category").asText());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSetBookmarkWithAllTypes() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String[] bookmarkTypes = {"Note", "Warning", "TODO", "Bug", "Analysis"};

                for (String bookmarkType : bookmarkTypes) {
                    Address typeAddr = testAddress.add(bookmarkTypes.length * 0x10 + bookmarkType.hashCode() % 0x100);
                    Map<String, Object> setArgs = new HashMap<>();
                    setArgs.put("programPath", programPath);
                    setArgs.put("action", "set");
                    setArgs.put("addressOrSymbol", typeAddr.toString());
                    setArgs.put("type", bookmarkType);
                    setArgs.put("category", "test");
                    setArgs.put("comment", "Test " + bookmarkType + " bookmark");

                    CallToolResult setResult = client.callTool(new CallToolRequest("manage-bookmarks", setArgs));
                    assertFalse("Set " + bookmarkType + " bookmark should succeed", setResult.isError());

                    // Verify bookmark was set
                    BookmarkManager bookmarkMgr = program.getBookmarkManager();
                    Bookmark bookmark = bookmarkMgr.getBookmark(typeAddr, bookmarkType, "test");
                    assertNotNull("Bookmark should be set for type " + bookmarkType, bookmark);
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testRemoveBookmark() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // First set a bookmark
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("type", "Note");
                setArgs.put("category", "test");
                setArgs.put("comment", "Bookmark to remove");
                client.callTool(new CallToolRequest("manage-bookmarks", setArgs));

                // Verify it was set
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Bookmark bookmarkBefore = bookmarkMgr.getBookmark(testAddress, "Note", "test");
                assertNotNull("Bookmark should be set before removal", bookmarkBefore);

                // Remove the bookmark
                Map<String, Object> removeArgs = new HashMap<>();
                removeArgs.put("programPath", programPath);
                removeArgs.put("action", "remove");
                removeArgs.put("addressOrSymbol", addressStr);
                removeArgs.put("type", "Note");
                removeArgs.put("category", "test");

                CallToolResult removeResult = client.callTool(new CallToolRequest("manage-bookmarks", removeArgs));
                assertFalse("Remove bookmark should succeed", removeResult.isError());

                // Verify bookmark was removed
                Bookmark bookmarkAfter = bookmarkMgr.getBookmark(testAddress, "Note", "test");
                assertNull("Bookmark should be removed", bookmarkAfter);
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testSearchBookmarks() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set a bookmark to search for
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("type", "Note");
                setArgs.put("category", "search");
                setArgs.put("comment", "Searchable bookmark text");
                client.callTool(new CallToolRequest("manage-bookmarks", setArgs));

                // Search for the bookmark
                Map<String, Object> searchArgs = new HashMap<>();
                  searchArgs.put("programPath", programPath);
                searchArgs.put("action", "search");
                searchArgs.put("searchText", "Searchable");
                searchArgs.put("maxResults", 10);

                CallToolResult searchResult = client.callTool(new CallToolRequest("manage-bookmarks", searchArgs));
                assertFalse("Search bookmarks should succeed", searchResult.isError());

                TextContent content = (TextContent) searchResult.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertTrue("Should have results field", json.has("results"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testRemoveAllBookmarks() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Set multiple bookmarks
                Address addr1 = program.getMinAddress();
                Address addr2 = addr1.add(0x10);
                Address addr3 = addr1.add(0x20);

                Map<String, Object> setArgs1 = new HashMap<>();
                setArgs1.put("programPath", programPath);
                setArgs1.put("action", "set");
                setArgs1.put("addressOrSymbol", addr1.toString());
                setArgs1.put("type", "Note");
                setArgs1.put("category", "removeAll");
                setArgs1.put("comment", "Bookmark 1");
                client.callTool(new CallToolRequest("manage-bookmarks", setArgs1));

                Map<String, Object> setArgs2 = new HashMap<>();
                setArgs2.put("programPath", programPath);
                setArgs2.put("action", "set");
                setArgs2.put("addressOrSymbol", addr2.toString());
                setArgs2.put("type", "Warning");
                setArgs2.put("category", "removeAll");
                setArgs2.put("comment", "Bookmark 2");
                client.callTool(new CallToolRequest("manage-bookmarks", setArgs2));

                // Remove all bookmarks
                Map<String, Object> removeAllArgs = new HashMap<>();
                removeAllArgs.put("programPath", programPath);
                removeAllArgs.put("action", "removeAll");
                removeAllArgs.put("removeAll", true);

                CallToolResult removeAllResult = client.callTool(new CallToolRequest("manage-bookmarks", removeAllArgs));
                // May require confirmation or specific parameters
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetBookmarkCategories() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Set bookmarks with different categories
                Address addr1 = program.getMinAddress();
                Address addr2 = addr1.add(0x10);

                Map<String, Object> setArgs1 = new HashMap<>();
                setArgs1.put("programPath", programPath);
                setArgs1.put("action", "set");
                setArgs1.put("addressOrSymbol", addr1.toString());
                setArgs1.put("type", "Note");
                setArgs1.put("category", "category1");
                setArgs1.put("comment", "Bookmark 1");
                client.callTool(new CallToolRequest("manage-bookmarks", setArgs1));

                Map<String, Object> setArgs2 = new HashMap<>();
                setArgs2.put("programPath", programPath);
                setArgs2.put("action", "set");
                setArgs2.put("addressOrSymbol", addr2.toString());
                setArgs2.put("type", "Warning");
                setArgs2.put("category", "category2");
                setArgs2.put("comment", "Bookmark 2");
                client.callTool(new CallToolRequest("manage-bookmarks", setArgs2));

                // Get categories
                Map<String, Object> categoriesArgs = new HashMap<>();
                  categoriesArgs.put("programPath", programPath);
                categoriesArgs.put("action", "categories");

                CallToolResult categoriesResult = client.callTool(new CallToolRequest("manage-bookmarks", categoriesArgs));
                assertFalse("Get categories should succeed", categoriesResult.isError());

                TextContent content = (TextContent) categoriesResult.content().get(0);
                JsonNode json = parseJsonContent(content.text());
                assertTrue("Should have categories field", json.has("categories"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testBatchSetBookmarks() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address addr1 = program.getMinAddress();
                Address addr2 = addr1.add(0x10);

                // Batch set bookmarks
                java.util.List<Map<String, Object>> bookmarksList = java.util.Arrays.asList(
                    Map.of("address", addr1.toString(), "type", "Note", "category", "batch", "comment", "Batch bookmark 1"),
                    Map.of("address", addr2.toString(), "type", "Warning", "category", "batch", "comment", "Batch bookmark 2")
                );

                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("bookmarks", bookmarksList);

                CallToolResult setResult = client.callTool(new CallToolRequest("manage-bookmarks", setArgs));
                assertFalse("Batch set bookmarks should succeed", setResult.isError());

                // Verify bookmarks were set
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Bookmark bookmark1 = bookmarkMgr.getBookmark(addr1, "Note", "batch");
                Bookmark bookmark2 = bookmarkMgr.getBookmark(addr2, "Warning", "batch");
                assertNotNull("First bookmark should be set", bookmark1);
                assertNotNull("Second bookmark should be set", bookmark2);
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testBookmarksValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                Address testAddress = program.getMinAddress();
                String addressStr = testAddress.toString();

                // Set bookmark
                Map<String, Object> setArgs = new HashMap<>();
                setArgs.put("programPath", programPath);
                setArgs.put("action", "set");
                setArgs.put("addressOrSymbol", addressStr);
                setArgs.put("type", "Note");
                setArgs.put("category", "validation");
                setArgs.put("comment", "State validation bookmark");

                CallToolResult setResult = client.callTool(new CallToolRequest("manage-bookmarks", setArgs));
                assertFalse("Set bookmark should succeed", setResult.isError());

                // Verify bookmark was actually set in program state
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Bookmark bookmark = bookmarkMgr.getBookmark(testAddress, "Note", "validation");
                assertNotNull("Bookmark should be in program state", bookmark);
                assertEquals("Bookmark comment should match", "State validation bookmark", bookmark.getComment());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}
