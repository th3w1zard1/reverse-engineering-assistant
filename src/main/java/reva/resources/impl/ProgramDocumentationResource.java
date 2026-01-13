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
package reva.resources.impl;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import reva.plugin.RevaProgramManager;
import reva.resources.AbstractResourceProvider;
import reva.util.AddressUtil;
import reva.util.SymbolUtil;

/**
 * Resource provider that exposes comprehensive program documentation in a DAG-like structure.
 * Includes all functions, symbols, strings, comments, tags, bookmarks, and their relationships.
 * Designed to facilitate generation of C# XML documentation comments from reverse engineering efforts.
 */
public class ProgramDocumentationResource extends AbstractResourceProvider {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String RESOURCE_ID = "ghidra://program-documentation";
    private static final String RESOURCE_NAME = "program-documentation";
    private static final String RESOURCE_DESCRIPTION = "Comprehensive program documentation in DAG format (functions, symbols, comments, tags, bookmarks, relationships)";
    private static final String RESOURCE_MIME_TYPE = "application/json";

    /**
     * Constructor
     * @param server The MCP server to register with
     */
    public ProgramDocumentationResource(McpSyncServer server) {
        super(server);
    }

    @Override
    public void register() {
        Resource resource = new Resource(
            RESOURCE_ID,
            RESOURCE_NAME,
            RESOURCE_DESCRIPTION,
            RESOURCE_MIME_TYPE,
            null  // No schema needed for this resource
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                return generateResourceContents();
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME + " with subscription support");
    }

    /**
     * Generate the current resource contents for the program documentation resource.
     * This method is called both for read requests and when notifying subscribers.
     *
     * @return ReadResourceResult containing all program documentation resource contents
     */
    private ReadResourceResult generateResourceContents() {
        List<ResourceContents> resourceContents = new ArrayList<>();

        // Get all open programs
        List<Program> openPrograms = RevaProgramManager.getOpenPrograms();

        for (Program program : openPrograms) {
            try {
                // Generate comprehensive documentation for this program
                Map<String, Object> documentation = generateProgramDocumentation(program);

                // Serialize to JSON
                String jsonString = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(documentation);

                // Add to resource contents
                // URL encode the program path to ensure URI safety
                String programPath = program.getDomainFile().getPathname();
                String encodedProgramPath = URLEncoder.encode(programPath, StandardCharsets.UTF_8);
                resourceContents.add(
                    new TextResourceContents(
                        RESOURCE_ID + "/" + encodedProgramPath,
                        RESOURCE_MIME_TYPE,
                        jsonString
                    )
                );
            } catch (JsonProcessingException e) {
                logError("Error serializing program documentation", e);
            } catch (Exception e) {
                logError("Error generating program documentation", e);
            }
        }

        return new ReadResourceResult(resourceContents);
    }

    /**
     * Generate comprehensive documentation for a program in DAG format.
     *
     * @param program The program to document
     * @return Map containing all program documentation
     */
    private Map<String, Object> generateProgramDocumentation(Program program) {
        Map<String, Object> doc = new HashMap<>();

        // Program metadata
        doc.put("programPath", program.getDomainFile().getPathname());
        doc.put("language", program.getLanguage().getLanguageID().getIdAsString());
        doc.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        doc.put("sizeBytes", program.getMemory().getSize());

        // DAG structure: nodes and edges
        Map<String, Object> dag = new HashMap<>();
        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        // Collect all functions
        Map<Address, Map<String, Object>> functionNodes = collectFunctions(program, nodes);

        // Collect all symbols
        collectSymbols(program, nodes);

        // Collect all strings
        collectStrings(program, nodes);

        // Collect all bookmarks
        collectBookmarks(program, nodes);

        // Collect all comments
        collectComments(program, nodes);

        // Build edges (relationships)
        buildEdges(program, functionNodes, edges);

        dag.put("nodes", nodes);
        dag.put("edges", edges);
        doc.put("dag", dag);

        // Summary statistics
        Map<String, Object> summary = new HashMap<>();
        summary.put("totalNodes", nodes.size());
        summary.put("totalEdges", edges.size());
        summary.put("functionCount", functionNodes.size());
        doc.put("summary", summary);

        return doc;
    }

    /**
     * Collect all functions and their metadata.
     *
     * @param program The program
     * @param nodes List to add function nodes to
     * @return Map of function address to function node data
     */
    private Map<Address, Map<String, Object>> collectFunctions(Program program, List<Map<String, Object>> nodes) {
        Map<Address, Map<String, Object>> functionMap = new HashMap<>();
        FunctionManager funcMgr = program.getFunctionManager();
        FunctionIterator functions = funcMgr.getFunctions(true);

        while (functions.hasNext()) {
            Function function = functions.next();
            Address entryPoint = function.getEntryPoint();

            Map<String, Object> node = new HashMap<>();
            node.put("id", "func:" + AddressUtil.formatAddress(entryPoint));
            node.put("type", "function");
            node.put("name", function.getName());
            node.put("address", AddressUtil.formatAddress(entryPoint));
            node.put("endAddress", AddressUtil.formatAddress(function.getBody().getMaxAddress()));
            node.put("sizeBytes", function.getBody().getNumAddresses());
            node.put("signature", function.getSignature().toString());
            node.put("returnType", function.getReturnType().toString());
            node.put("isExternal", function.isExternal());
            node.put("isThunk", function.isThunk());
            node.put("isDefaultName", SymbolUtil.isDefaultSymbolName(function.getName()));

            // Parameters
            List<Map<String, Object>> parameters = new ArrayList<>();
            for (int i = 0; i < function.getParameterCount(); i++) {
                ghidra.program.model.listing.Parameter param = function.getParameter(i);
                Map<String, Object> paramData = new HashMap<>();
                paramData.put("name", param.getName());
                paramData.put("dataType", param.getDataType().toString());
                String paramComment = param.getComment();
                if (paramComment != null && !paramComment.isEmpty()) {
                    paramData.put("comment", paramComment);
                }
                parameters.add(paramData);
            }
            node.put("parameters", parameters);

            // Function comment
            String functionComment = function.getComment();
            if (functionComment != null && !functionComment.isEmpty()) {
                node.put("comment", functionComment);
            }

            // Function tags
            List<String> tags = new ArrayList<>();
            Set<FunctionTag> functionTags = function.getTags();
            for (FunctionTag tag : functionTags) {
                tags.add(tag.getName());
            }
            if (!tags.isEmpty()) {
                node.put("tags", tags);
            }

            // Local variables (if available)
            try {
                List<Map<String, Object>> variables = new ArrayList<>();
                ghidra.program.model.listing.Variable[] vars = function.getLocalVariables();
                for (ghidra.program.model.listing.Variable var : vars) {
                    Map<String, Object> varData = new HashMap<>();
                    varData.put("name", var.getName());
                    varData.put("dataType", var.getDataType().toString());
                    varData.put("offset", var.getStackOffset());
                    String varComment = var.getComment();
                    if (varComment != null && !varComment.isEmpty()) {
                        varData.put("comment", varComment);
                    }
                    variables.add(varData);
                }
                if (!variables.isEmpty()) {
                    node.put("localVariables", variables);
                }
            } catch (Exception e) {
                // Ignore errors getting local variables
            }

            nodes.add(node);
            functionMap.put(entryPoint, node);
        }

        return functionMap;
    }

    /**
     * Collect all symbols and their metadata.
     *
     * @param program The program
     * @param nodes List to add symbol nodes to
     */
    private void collectSymbols(Program program, List<Map<String, Object>> nodes) {
        SymbolTable symbolTable = program.getSymbolTable();
        Iterator<Symbol> symbols = symbolTable.getAllSymbols(false);

        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();

            // Skip default/auto-generated symbols
            if (SymbolUtil.isDefaultSymbolName(symbol.getName())) {
                continue;
            }

            Map<String, Object> node = new HashMap<>();
            node.put("id", "sym:" + AddressUtil.formatAddress(symbol.getAddress()));
            node.put("type", "symbol");
            node.put("name", symbol.getName());
            node.put("address", AddressUtil.formatAddress(symbol.getAddress()));
            node.put("symbolType", symbol.getSymbolType().toString());
            node.put("isPrimary", symbol.isPrimary());
            node.put("isExternal", symbol.isExternal());
            node.put("isGlobal", symbol.isGlobal());
            // A symbol is local if it's not global and its namespace is a function
            boolean isLocal = !symbol.isGlobal() && symbol.getParentNamespace() instanceof Function;
            node.put("isLocal", isLocal);

            // Symbol namespace/parent
            if (symbol.getParentNamespace() != null) {
                node.put("namespace", symbol.getParentNamespace().getName(true));
            }

            nodes.add(node);
        }
    }

    /**
     * Collect all strings referenced in the program.
     *
     * @param program The program
     * @param nodes List to add string nodes to
     */
    private void collectStrings(Program program, List<Map<String, Object>> nodes) {
        Set<String> seenStrings = new HashSet<>();
        Listing listing = program.getListing();

        // Iterate over all defined data to find strings
        ghidra.program.model.listing.DataIterator dataIterator = listing.getDefinedData(true);
        for (ghidra.program.model.listing.Data data : dataIterator) {
            if (!(data.getValue() instanceof String)) {
                continue;
            }

            String stringValue = (String) data.getValue();
            if (stringValue != null && stringValue.length() > 1 && !seenStrings.contains(stringValue)) {
                seenStrings.add(stringValue);

                Address addr = data.getAddress();
                Map<String, Object> node = new HashMap<>();
                node.put("id", "str:" + AddressUtil.formatAddress(addr));
                node.put("type", "string");
                node.put("value", stringValue);
                node.put("address", AddressUtil.formatAddress(addr));
                node.put("length", stringValue.length());

                nodes.add(node);
            }
        }
    }

    /**
     * Collect all bookmarks.
     *
     * @param program The program
     * @param nodes List to add bookmark nodes to
     */
    private void collectBookmarks(Program program, List<Map<String, Object>> nodes) {
        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        Iterator<Bookmark> bookmarks = bookmarkMgr.getBookmarksIterator();

        while (bookmarks.hasNext()) {
            Bookmark bookmark = bookmarks.next();
            Address addr = bookmark.getAddress();

            Map<String, Object> node = new HashMap<>();
            node.put("id", "bm:" + AddressUtil.formatAddress(addr) + ":" + bookmark.getType() + ":" + bookmark.getCategory());
            node.put("type", "bookmark");
            node.put("address", AddressUtil.formatAddress(addr));
            node.put("bookmarkType", bookmark.getType());
            node.put("category", bookmark.getCategory());
            String comment = bookmark.getComment();
            if (comment != null && !comment.isEmpty()) {
                node.put("comment", comment);
            }

            nodes.add(node);
        }
    }

    /**
     * Collect all comments in the program.
     *
     * @param program The program
     * @param nodes List to add comment nodes to
     */
    private void collectComments(Program program, List<Map<String, Object>> nodes) {
        Listing listing = program.getListing();

        // Collect comments by type
        CommentType[] commentTypes = {
            CommentType.PRE,
            CommentType.EOL,
            CommentType.POST,
            CommentType.PLATE,
            CommentType.REPEATABLE
        };

        for (CommentType commentType : commentTypes) {
            AddressIterator addrIter = listing.getCommentAddressIterator(commentType, program.getMemory(), true);
            while (addrIter.hasNext()) {
                Address addr = addrIter.next();
                String comment = listing.getComment(commentType, addr);
                if (comment != null && !comment.isEmpty()) {
                    Map<String, Object> node = new HashMap<>();
                    node.put("id", "cmt:" + AddressUtil.formatAddress(addr) + ":" + commentType.name());
                    node.put("type", "comment");
                    node.put("address", AddressUtil.formatAddress(addr));
                    node.put("commentType", commentType.name().toLowerCase());
                    node.put("comment", comment);

                    nodes.add(node);
                }
            }
        }
    }

    /**
     * Build edges representing relationships between nodes.
     *
     * @param program The program
     * @param functionNodes Map of function addresses to function node data
     * @param edges List to add edges to
     */
    private void buildEdges(Program program, Map<Address, Map<String, Object>> functionNodes, List<Map<String, Object>> edges) {
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();

        // Build call graph edges (function -> function)
        for (Map.Entry<Address, Map<String, Object>> entry : functionNodes.entrySet()) {
            Address fromFuncAddr = entry.getKey();
            String fromId = (String) entry.getValue().get("id");

            // Get all references from this function
            Reference[] refsFrom = refMgr.getReferencesFrom(fromFuncAddr);
            for (Reference ref : refsFrom) {
                Address toAddr = ref.getToAddress();

                // Check if target is a function
                Function targetFunc = funcMgr.getFunctionAt(toAddr);
                if (targetFunc == null) {
                    targetFunc = funcMgr.getFunctionContaining(toAddr);
                }

                if (targetFunc != null && ref.getReferenceType().isCall()) {
                    Address targetEntry = targetFunc.getEntryPoint();
                    Map<String, Object> targetNode = functionNodes.get(targetEntry);
                    if (targetNode != null) {
                        String toId = (String) targetNode.get("id");

                        Map<String, Object> edge = new HashMap<>();
                        edge.put("from", fromId);
                        edge.put("to", toId);
                        edge.put("type", "calls");
                        edge.put("referenceAddress", AddressUtil.formatAddress(ref.getFromAddress()));
                        edges.add(edge);
                    }
                }
            }
        }

        // Build reference edges (functions -> symbols, strings, etc.)
        FunctionIterator functions = funcMgr.getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            String funcId = "func:" + AddressUtil.formatAddress(function.getEntryPoint());

            // Get references from this function
            Reference[] refsFrom = refMgr.getReferencesFrom(function.getEntryPoint());
            for (Reference ref : refsFrom) {

                Address toAddr = ref.getToAddress();
                String toId = null;
                String edgeType = null;

                // Check if target is a symbol
                SymbolTable symbolTable = program.getSymbolTable();
                Symbol symbol = symbolTable.getPrimarySymbol(toAddr);
                if (symbol != null && !SymbolUtil.isDefaultSymbolName(symbol.getName())) {
                    toId = "sym:" + AddressUtil.formatAddress(toAddr);
                    edgeType = "references_symbol";
                } else {
                    // Check if target is a string
                    Listing listing = program.getListing();
                    CodeUnit cu = listing.getCodeUnitAt(toAddr);
                    if (cu != null && cu instanceof ghidra.program.model.listing.Data) {
                        ghidra.program.model.listing.Data data = (ghidra.program.model.listing.Data) cu;
                        if (data.getValue() instanceof String) {
                            String stringValue = (String) data.getValue();
                            if (stringValue != null && stringValue.length() > 1) {
                                toId = "str:" + AddressUtil.formatAddress(toAddr);
                                edgeType = "references_string";
                            }
                        }
                    }
                }

                if (toId != null && edgeType != null) {
                    Map<String, Object> edge = new HashMap<>();
                    edge.put("from", funcId);
                    edge.put("to", toId);
                    edge.put("type", edgeType);
                    edge.put("referenceAddress", AddressUtil.formatAddress(ref.getFromAddress()));
                    edges.add(edge);
                }
            }
        }
    }

    @Override
    public void programOpened(Program program) {
        // Notify subscribers that the resource has changed
        notifyResourceChanged();
    }

    @Override
    public void programClosed(Program program) {
        // Notify subscribers that the resource has changed
        notifyResourceChanged();
    }

    /**
     * Notify all subscribers that the resource content has changed.
     */
    private void notifyResourceChanged() {
        try {
            // Generate updated resource contents
            ReadResourceResult newContents = generateResourceContents();

            // Attempt multiple notification approaches for maximum compatibility
            boolean notified = false;

            // Approach 1: Try notifyResourceChanged method (if it exists in SDK)
            try {
                java.lang.reflect.Method notifyMethod = server.getClass().getMethod(
                    "notifyResourceChanged", String.class, ReadResourceResult.class);
                notifyMethod.invoke(server, RESOURCE_ID, newContents);
                notified = true;
                logInfo("Notified subscribers via notifyResourceChanged: " + RESOURCE_NAME);
            } catch (NoSuchMethodException e) {
                // Method doesn't exist, try next approach
            } catch (Exception e) {
                logError("Error invoking notifyResourceChanged", e);
            }

            // Approach 2: Try sendResourceUpdatedNotification (alternative SDK method name)
            if (!notified) {
                try {
                    java.lang.reflect.Method sendMethod = server.getClass().getMethod(
                        "sendResourceUpdatedNotification", String.class);
                    sendMethod.invoke(server, RESOURCE_ID);
                    notified = true;
                    logInfo("Notified subscribers via sendResourceUpdatedNotification: " + RESOURCE_NAME);
                } catch (NoSuchMethodException e) {
                    // Method doesn't exist, try next approach
                } catch (Exception e) {
                    logError("Error invoking sendResourceUpdatedNotification", e);
                }
            }

            // Approach 3: SDK may handle notifications automatically
            if (!notified) {
                logInfo("Resource changed: " + RESOURCE_NAME +
                    " (MCP SDK should handle subscription notifications automatically)");
            }
        } catch (Exception e) {
            logError("Error notifying resource change", e);
        }
    }
}
