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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for bookmark-related operations.
 * Provides tools to set, get, remove, and search bookmarks in programs.
 */
public class BookmarkToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public BookmarkToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerManageBookmarksTool();
    }

    private void registerManageBookmarksTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("action", Map.of(
            "type", "string",
            "description", "Action to perform: 'set', 'get', 'search', 'remove', or 'categories'",
            "enum", List.of("set", "get", "search", "remove", "categories")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address where to set/get/remove the bookmark (required for set/remove, optional for get)"));
        properties.put("address_or_symbol", SchemaUtil.stringProperty("Address or symbol name (alternative parameter name)"));
        properties.put("type", SchemaUtil.stringProperty("Bookmark type enum ('Note', 'Warning', 'TODO', 'Bug', 'Analysis'; required for set/remove, optional for get/categories)"));
        properties.put("category", SchemaUtil.stringProperty("Bookmark category for organization (required for set, optional for remove; can be empty string)"));
        properties.put("comment", SchemaUtil.stringProperty("Bookmark comment text (required for set)"));
        properties.put("search_text", SchemaUtil.stringProperty("Text to search for in bookmark comments when action='search' (required for search)"));
        properties.put("max_results", SchemaUtil.integerPropertyWithDefault("Maximum number of results to return when action='search'", 100));

        List<String> required = List.of("programPath", "action");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("manage-bookmarks")
            .title("Manage Bookmarks")
            .description("Create, retrieve, search, remove bookmarks, or list bookmark categories.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String action = getString(request, "action");

                switch (action) {
                    case "set":
                        return handleSetBookmark(program, request);
                    case "get":
                        return handleGetBookmarks(program, request);
                    case "search":
                        return handleSearchBookmarks(program, request);
                    case "remove":
                        return handleRemoveBookmark(program, request);
                    case "categories":
                        return handleListCategories(program, request);
                    default:
                        return createErrorResult("Invalid action: " + action + ". Valid actions are: set, get, search, remove, categories");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in manage-bookmarks", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleSetBookmark(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }
        if (addressStr == null) {
            return createErrorResult("address is required for action='set'");
        }
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }
        String type = getString(request, "type");
        String category = getString(request, "category");
        String comment = getString(request, "comment");

        try {
            int transactionId = program.startTransaction("Set Bookmark");
            try {
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Bookmark existing = bookmarkMgr.getBookmark(address, type, category);
                if (existing != null) {
                    bookmarkMgr.removeBookmark(existing);
                }
                Bookmark bookmark = bookmarkMgr.setBookmark(address, type, category, comment);
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("id", bookmark.getId());
                result.put("address", AddressUtil.formatAddress(address));
                result.put("type", type);
                result.put("category", category);
                result.put("comment", comment);
                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Set bookmark");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error setting bookmark", e);
            return createErrorResult("Failed to set bookmark: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleGetBookmarks(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }
        String typeFilter = getOptionalString(request, "type", null);
        String categoryFilter = getOptionalString(request, "category", null);

        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        List<Map<String, Object>> bookmarks = new ArrayList<>();

        if (addressStr != null) {
            Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
            if (address == null) {
                return createErrorResult("Could not resolve address or symbol: " + addressStr);
            }
            Bookmark[] bookmarksAtAddr = bookmarkMgr.getBookmarks(address);
            for (Bookmark bookmark : bookmarksAtAddr) {
                if (matchesFilters(bookmark, typeFilter, categoryFilter)) {
                    bookmarks.add(bookmarkToMap(bookmark));
                }
            }
        } else {
            Iterator<Bookmark> iter = typeFilter != null ? bookmarkMgr.getBookmarksIterator(typeFilter) : bookmarkMgr.getBookmarksIterator();
            while (iter.hasNext()) {
                Bookmark bookmark = iter.next();
                if (matchesFilters(bookmark, typeFilter, categoryFilter)) {
                    bookmarks.add(bookmarkToMap(bookmark));
                }
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("bookmarks", bookmarks);
        result.put("count", bookmarks.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSearchBookmarks(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String searchText = getOptionalString(request, "search_text", null);
        if (searchText == null) {
            searchText = getOptionalString(request, "searchText", null);
        }
        if (searchText == null || searchText.trim().isEmpty()) {
            return createErrorResult("search_text is required for action='search'");
        }
        String typeFilter = getOptionalString(request, "type", null);
        int maxResults = getOptionalInt(request, "max_results", getOptionalInt(request, "maxResults", 100));

        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        List<Map<String, Object>> results = new ArrayList<>();
        Iterator<Bookmark> iter = bookmarkMgr.getBookmarksIterator();

        String searchTextLower = searchText.toLowerCase();
        while (iter.hasNext() && results.size() < maxResults) {
            Bookmark bookmark = iter.next();
            if (typeFilter != null && !bookmark.getTypeString().equals(typeFilter)) {
                continue;
            }
            String comment = bookmark.getComment();
            if (comment == null || !comment.toLowerCase().contains(searchTextLower)) {
                continue;
            }
            results.add(bookmarkToMap(bookmark));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("results", results);
        result.put("count", results.size());
        result.put("maxResults", maxResults);
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleRemoveBookmark(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }
        if (addressStr == null) {
            return createErrorResult("address is required for action='remove'");
        }
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }
        String type = getString(request, "type");
        String category = getOptionalString(request, "category", "");

        try {
            int transactionId = program.startTransaction("Remove Bookmark");
            try {
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Bookmark bookmark = bookmarkMgr.getBookmark(address, type, category);
                if (bookmark == null) {
                    return createErrorResult("No bookmark found at address " + AddressUtil.formatAddress(address) +
                        " with type " + type + " and category " + category);
                }
                bookmarkMgr.removeBookmark(bookmark);
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("address", AddressUtil.formatAddress(address));
                result.put("type", type);
                result.put("category", category);
                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Remove bookmark");
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error removing bookmark", e);
            return createErrorResult("Failed to remove bookmark: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult handleListCategories(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String type = getOptionalString(request, "type", null);
        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        Map<String, Integer> categoryCounts = new HashMap<>();
        Iterator<Bookmark> iter = type != null ? bookmarkMgr.getBookmarksIterator(type) : bookmarkMgr.getBookmarksIterator();

        while (iter.hasNext()) {
            Bookmark bookmark = iter.next();
            if (type == null || bookmark.getTypeString().equals(type)) {
                String category = bookmark.getCategory();
                categoryCounts.put(category, categoryCounts.getOrDefault(category, 0) + 1);
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("categories", categoryCounts);
        if (type != null) {
            result.put("type", type);
        }
        return createJsonResult(result);
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Check if a bookmark matches the given filters
     * @param bookmark The bookmark to check
     * @param typeFilter Type filter (null for any)
     * @param categoryFilter Category filter (null for any)
     * @return true if bookmark matches filters
     */
    private boolean matchesFilters(Bookmark bookmark, String typeFilter, String categoryFilter) {
        if (typeFilter != null && !bookmark.getTypeString().equals(typeFilter)) {
            return false;
        }
        if (categoryFilter != null && !bookmark.getCategory().equals(categoryFilter)) {
            return false;
        }
        return true;
    }

    /**
     * Convert a bookmark to a map representation
     * @param bookmark The bookmark to convert
     * @return Map representation of the bookmark
     */
    private Map<String, Object> bookmarkToMap(Bookmark bookmark) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", bookmark.getId());
        map.put("address", AddressUtil.formatAddress(bookmark.getAddress()));
        map.put("type", bookmark.getTypeString());
        map.put("category", bookmark.getCategory());
        map.put("comment", bookmark.getComment());
        return map;
    }
}
