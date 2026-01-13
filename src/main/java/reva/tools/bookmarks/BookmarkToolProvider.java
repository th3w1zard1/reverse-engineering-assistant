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
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for bookmark-related operations. Provides tools to set, get,
 * remove, and search bookmarks in programs.
 */
public class BookmarkToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     *
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
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser."));
        properties.put("action", Map.of(
                "type", "string",
                "description", "Action to perform: 'set', 'get', 'search', 'remove', 'remove_all', or 'categories'",
                "enum", List.of("set", "get", "search", "remove", "remove_all", "categories")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address where to set/get/remove the bookmark (required for set/remove, optional for get)"));
        properties.put("address_or_symbol", SchemaUtil.stringProperty("Address or symbol name (alternative parameter name)"));
        properties.put("type", SchemaUtil.stringProperty("Bookmark type enum ('Note', 'Warning', 'TODO', 'Bug', 'Analysis'; required for set/remove, optional for get/categories)"));
        properties.put("category", SchemaUtil.stringProperty("Bookmark category for organization (required for set, optional for remove; can be empty string)"));
        properties.put("comment", SchemaUtil.stringProperty("Bookmark comment text (required for set when not using batch mode)"));
        // Batch bookmarks array - array of objects
        Map<String, Object> bookmarkItemSchema = new HashMap<>();
        bookmarkItemSchema.put("type", "object");
        Map<String, Object> bookmarkItemProperties = new HashMap<>();
        bookmarkItemProperties.put("address", SchemaUtil.stringProperty("Address or symbol name where to set the bookmark"));
        bookmarkItemProperties.put("type", SchemaUtil.stringProperty("Bookmark type enum ('Note', 'Warning', 'TODO', 'Bug', 'Analysis')"));
        bookmarkItemProperties.put("category", SchemaUtil.stringProperty("Bookmark category for organization (can be empty string)"));
        bookmarkItemProperties.put("comment", SchemaUtil.stringProperty("Bookmark comment text"));
        bookmarkItemSchema.put("properties", bookmarkItemProperties);
        bookmarkItemSchema.put("required", List.of("address", "type", "comment"));

        Map<String, Object> bookmarksArraySchema = new HashMap<>();
        bookmarksArraySchema.put("type", "array");
        bookmarksArraySchema.put("description", "Array of bookmark objects for batch setting. Each object should have 'address' (required), 'type' (required), 'comment' (required), and optional 'category'. When provided, sets multiple bookmarks in a single transaction.");
        bookmarksArraySchema.put("items", bookmarkItemSchema);
        properties.put("bookmarks", bookmarksArraySchema);
        properties.put("search_text", SchemaUtil.stringProperty("Text to search for in bookmark comments when action='search' (required for search)"));
        properties.put("max_results", SchemaUtil.integerPropertyWithDefault("Maximum number of results to return when action='search'", 100));
        properties.put("remove_all", SchemaUtil.booleanPropertyWithDefault("When true with action='remove', removes all bookmarks from the program. Can be combined with 'type' and 'category' filters to remove all bookmarks of a specific type/category.", false));

        List<String> required = List.of("action");

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
                    case "remove_all":
                        return handleRemoveAllBookmarks(program, request);
                    case "categories":
                        return handleListCategories(program, request);
                    default:
                        return createErrorResult("Invalid action: " + action + ". Valid actions are: set, get, search, remove, remove_all, categories");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in manage-bookmarks", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    /**
     * Handle setting a bookmark
     *
     * @param program The program
     * @param request The request
     * @return The result
     */
    private McpSchema.CallToolResult handleSetBookmark(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        // Check for batch mode (bookmarks array)
        List<Map<String, Object>> bookmarksArray = getOptionalBookmarksArray(request);

        if (bookmarksArray != null && !bookmarksArray.isEmpty()) {
            return handleBatchSetBookmarks(program, bookmarksArray);
        }

        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }
        if (addressStr == null) {
            return createErrorResult("address is required for action='set' (or use 'bookmarks' array for batch mode)");
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

    /**
     * Get optional bookmarks array from request for batch operations
     *
     * @param request The request
     * @return The bookmarks array
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getOptionalBookmarksArray(io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        Object value = request.arguments().get("bookmarks");
        if (value == null) {
            return null;
        }
        if (value instanceof List) {
            return (List<Map<String, Object>>) value;
        }
        throw new IllegalArgumentException("Parameter 'bookmarks' must be an array");
    }

    /**
     * Handle batch setting of multiple bookmarks in a single transaction
     *
     * @param program The program
     * @param bookmarksArray The bookmarks array
     * @return The result
     */
    private McpSchema.CallToolResult handleBatchSetBookmarks(Program program,
            List<Map<String, Object>> bookmarksArray) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        BookmarkManager bookmarkMgr = program.getBookmarkManager();

        try {
            int transactionId = program.startTransaction("Batch Set Bookmarks");
            try {
                for (int i = 0; i < bookmarksArray.size(); i++) {
                    Map<String, Object> bookmarkObj = bookmarksArray.get(i);

                    // Extract address
                    Object addressObj = bookmarkObj.get("address");
                    if (addressObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'address' field in bookmark object"));
                        continue;
                    }
                    String addressStr = addressObj.toString();

                    // Extract type
                    Object typeObj = bookmarkObj.get("type");
                    if (typeObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'type' field in bookmark object"));
                        continue;
                    }
                    String type = typeObj.toString();

                    // Extract comment
                    Object commentObj = bookmarkObj.get("comment");
                    if (commentObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'comment' field in bookmark object"));
                        continue;
                    }
                    String comment = commentObj.toString();

                    // Extract category (optional, defaults to empty string)
                    String category = "";
                    Object categoryObj = bookmarkObj.get("category");
                    if (categoryObj != null) {
                        category = categoryObj.toString();
                    }

                    // Resolve address
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                    if (address == null) {
                        errors.add(createErrorInfo(i, "Could not resolve address or symbol: " + addressStr));
                        continue;
                    }

                    // Set the bookmark (remove existing if present)
                    Bookmark existing = bookmarkMgr.getBookmark(address, type, category);
                    if (existing != null) {
                        bookmarkMgr.removeBookmark(existing);
                    }
                    Bookmark bookmark = bookmarkMgr.setBookmark(address, type, category, comment);

                    // Record success
                    Map<String, Object> result = new HashMap<>();
                    result.put("index", i);
                    result.put("id", bookmark.getId());
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("type", type);
                    result.put("category", category);
                    result.put("comment", comment);
                    results.add(result);
                }

                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Batch set bookmarks");

                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("total", bookmarksArray.size());
                response.put("succeeded", results.size());
                response.put("failed", errors.size());
                response.put("results", results);
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                }

                return createJsonResult(response);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error in batch set bookmarks", e);
            return createErrorResult("Failed to batch set bookmarks: " + e.getMessage());
        }
    }

    /**
     * Create error info for batch operations
     *
     * @param index The index of the bookmark
     * @param message The error message
     * @return The error info
     */
    private Map<String, Object> createErrorInfo(int index, String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("index", index);
        error.put("error", message);
        return error;
    }

    /**
     * Handle getting bookmarks
     *
     * @param program The program
     * @param request The request
     * @return The result
     */
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

    /**
     * Handle searching bookmarks
     *
     * @param program The program
     * @param request The request
     * @return The result
     */
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

    /**
     * Handle removing a bookmark or batch of bookmarks
     *
     * @param program The program
     * @param request The request
     * @return The result
     */
    private McpSchema.CallToolResult handleRemoveBookmark(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        // Check for batch mode (bookmarks array)
        List<Map<String, Object>> bookmarksArray = getOptionalBookmarksArray(request);
        
        if (bookmarksArray != null && !bookmarksArray.isEmpty()) {
            return handleBatchRemoveBookmarks(program, bookmarksArray);
        }
        
        // Check for remove_all flag
        boolean removeAll = getOptionalBoolean(request, "remove_all", false);
        if (removeAll) {
            return handleRemoveAllBookmarks(program, request);
        }

        // Single bookmark removal
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            addressStr = getOptionalString(request, "address_or_symbol", null);
        }
        if (addressStr == null) {
            return createErrorResult("address is required for action='remove' (or use 'bookmarks' array for batch mode, or 'remove_all=true' to remove all)");
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
                    return createErrorResult("No bookmark found at address " + AddressUtil.formatAddress(address)
                            + " with type " + type + " and category " + category);
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
    
    /**
     * Handle batch removal of multiple bookmarks in a single transaction
     *
     * @param program The program
     * @param bookmarksArray The bookmarks array to remove
     * @return The result
     */
    private McpSchema.CallToolResult handleBatchRemoveBookmarks(Program program,
            List<Map<String, Object>> bookmarksArray) {
        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        BookmarkManager bookmarkMgr = program.getBookmarkManager();

        try {
            int transactionId = program.startTransaction("Batch Remove Bookmarks");
            try {
                for (int i = 0; i < bookmarksArray.size(); i++) {
                    Map<String, Object> bookmarkObj = bookmarksArray.get(i);

                    // Extract address
                    Object addressObj = bookmarkObj.get("address");
                    if (addressObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'address' field in bookmark object"));
                        continue;
                    }
                    String addressStr = addressObj.toString();

                    // Extract type
                    Object typeObj = bookmarkObj.get("type");
                    if (typeObj == null) {
                        errors.add(createErrorInfo(i, "Missing 'type' field in bookmark object"));
                        continue;
                    }
                    String type = typeObj.toString();

                    // Extract category (optional, defaults to empty string)
                    String category = "";
                    Object categoryObj = bookmarkObj.get("category");
                    if (categoryObj != null) {
                        category = categoryObj.toString();
                    }

                    // Resolve address
                    Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
                    if (address == null) {
                        errors.add(createErrorInfo(i, "Could not resolve address or symbol: " + addressStr));
                        continue;
                    }

                    // Remove the bookmark
                    Bookmark bookmark = bookmarkMgr.getBookmark(address, type, category);
                    if (bookmark == null) {
                        errors.add(createErrorInfo(i, "No bookmark found at address " + AddressUtil.formatAddress(address)
                                + " with type " + type + " and category " + category));
                        continue;
                    }
                    bookmarkMgr.removeBookmark(bookmark);

                    // Record success
                    Map<String, Object> result = new HashMap<>();
                    result.put("index", i);
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("type", type);
                    result.put("category", category);
                    results.add(result);
                }

                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Batch remove bookmarks");

                // Build response
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("total", bookmarksArray.size());
                response.put("removed", results.size());
                response.put("failed", errors.size());
                response.put("results", results);
                if (!errors.isEmpty()) {
                    response.put("errors", errors);
                }

                return createJsonResult(response);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error in batch remove bookmarks", e);
            return createErrorResult("Failed to batch remove bookmarks: " + e.getMessage());
        }
    }
    
    /**
     * Handle removing all bookmarks from a program
     *
     * @param program The program
     * @param request The request
     * @return The result
     */
    private McpSchema.CallToolResult handleRemoveAllBookmarks(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String typeFilter = getOptionalString(request, "type", null);
        String categoryFilter = getOptionalString(request, "category", null);
        
        try {
            int transactionId = program.startTransaction("Remove All Bookmarks");
            try {
                BookmarkManager bookmarkMgr = program.getBookmarkManager();
                Iterator<Bookmark> iter = typeFilter != null 
                    ? bookmarkMgr.getBookmarksIterator(typeFilter) 
                    : bookmarkMgr.getBookmarksIterator();
                
                int removedCount = 0;
                List<Map<String, Object>> removedBookmarks = new ArrayList<>();
                
                while (iter.hasNext()) {
                    Bookmark bookmark = iter.next();
                    
                    // Apply filters
                    if (typeFilter != null && !bookmark.getTypeString().equals(typeFilter)) {
                        continue;
                    }
                    if (categoryFilter != null && !bookmark.getCategory().equals(categoryFilter)) {
                        continue;
                    }
                    
                    // Record bookmark info before removing
                    Map<String, Object> bookmarkInfo = new HashMap<>();
                    bookmarkInfo.put("address", AddressUtil.formatAddress(bookmark.getAddress()));
                    bookmarkInfo.put("type", bookmark.getTypeString());
                    bookmarkInfo.put("category", bookmark.getCategory());
                    bookmarkInfo.put("comment", bookmark.getComment());
                    removedBookmarks.add(bookmarkInfo);
                    
                    bookmarkMgr.removeBookmark(bookmark);
                    removedCount++;
                }
                
                program.endTransaction(transactionId, true);
                autoSaveProgram(program, "Remove all bookmarks");
                
                Map<String, Object> result = new HashMap<>();
                result.put("success", true);
                result.put("removed", removedCount);
                result.put("bookmarks", removedBookmarks);
                if (typeFilter != null) {
                    result.put("typeFilter", typeFilter);
                }
                if (categoryFilter != null) {
                    result.put("categoryFilter", categoryFilter);
                }
                
                return createJsonResult(result);
            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }
        } catch (Exception e) {
            logError("Error removing all bookmarks", e);
            return createErrorResult("Failed to remove all bookmarks: " + e.getMessage());
        }
    }
    /**
     * Handle listing bookmark categories
     *
     * @param program The program
     * @param request The request
     * @return The result
     */
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
     *
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
     *
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
