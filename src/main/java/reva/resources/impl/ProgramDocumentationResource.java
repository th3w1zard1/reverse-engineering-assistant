package reva.resources.impl;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Variable;
import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import reva.plugin.RevaProgramManager;
import reva.resources.AbstractResourceProvider;
import reva.util.RevaInternalServiceRegistry;
import reva.util.AddressUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import generic.concurrent.GThreadPool;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Resource provider for comprehensive program documentation.
 * Provides ALL program data in structured JSON format:
 * - All functions (with parameters, variables, tags, comments)
 * - All comments (all types: pre, eol, post, plate, repeatable)
 * - All symbols/labels (with addresses, types, namespaces)
 * - All bookmarks (with type, category, comment, address)
 * - All strings (with addresses, content, length)
 * - All data types and structures
 * - Memory layout
 * - Imports/exports
 * - Function tags
 * - Cross-references summary
 * 
 * Uses caching to improve performance - documentation is regenerated only when programs change.
 */
public class ProgramDocumentationResource extends AbstractResourceProvider {
    private static final String RESOURCE_ID = "ghidra://program-documentation";
    private static final String RESOURCE_NAME = "program-documentation";
    private static final String RESOURCE_DESCRIPTION = "Comprehensive JSON documentation of all open programs - includes all functions, comments, labels, tags, bookmarks, strings, data types, and more";
    private static final String RESOURCE_MIME_TYPE = "application/json";
    private static final ObjectMapper JSON = new ObjectMapper();

    // Cache documentation per program to avoid regenerating on every request
    private final Map<Program, String> programDocumentationCache = new ConcurrentHashMap<>();
    // Track generation futures for each program to allow blocking waits
    private final Map<Program, CompletableFuture<String>> generationFutures = new ConcurrentHashMap<>();
    private volatile String cachedFullDocumentation = null;
    private volatile long cacheTimestamp = 0;
    private static final long CACHE_VALIDITY_MS = 30000; // Cache for 30 seconds
    private static final long GENERATION_TIMEOUT_SECONDS = 300; // 5 minutes for comprehensive generation

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
            null  // No schema needed for simple resources
        );

        SyncResourceSpecification resourceSpec = new SyncResourceSpecification(
            resource,
            (exchange, request) -> {
                List<ResourceContents> resourceContents = new ArrayList<>();

                try {
                    // Use cached documentation if available and recent
                    long now = System.currentTimeMillis();
                    if (cachedFullDocumentation != null && (now - cacheTimestamp) < CACHE_VALIDITY_MS) {
                        TextResourceContents cachedContent = new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            cachedFullDocumentation
                        );
                        resourceContents.add(cachedContent);
                        return new ReadResourceResult(resourceContents);
                    }

                    List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
                    
                    // DIAGNOSTIC: Log what getOpenPrograms() returned
                    logInfo("=== DIAGNOSTIC: getOpenPrograms() returned " + openPrograms.size() + " program(s) ===");
                    for (int i = 0; i < openPrograms.size(); i++) {
                        Program p = openPrograms.get(i);
                        logInfo("Program[" + i + "]: name='" + p.getName() + 
                                "', path='" + p.getDomainFile().getPathname() + 
                                "', closed=" + p.isClosed() + 
                                ", class=" + p.getClass().getName());
                    }

                    if (openPrograms.isEmpty()) {
                        ObjectNode emptyResult = JSON.createObjectNode();
                        emptyResult.put("programs", JSON.createArrayNode());
                        emptyResult.put("message", "No programs are currently open");
                        String emptyJson = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(emptyResult);
                        TextResourceContents emptyContent = new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            emptyJson
                        );
                        resourceContents.add(emptyContent);
                        cachedFullDocumentation = emptyJson;
                        cacheTimestamp = now;
                        return new ReadResourceResult(resourceContents);
                    }

                    // Ensure all programs have documentation - block and wait if needed
                    // NEVER return placeholder messages - always wait for complete data
                    for (Program program : openPrograms) {
                        logInfo("=== DIAGNOSTIC: Processing program: " + program.getName() + " ===");
                        String cachedDoc = programDocumentationCache.get(program);
                        logInfo("Cached doc exists: " + (cachedDoc != null) + ", length: " + (cachedDoc != null ? cachedDoc.length() : 0));
                        if (cachedDoc == null) {
                            // Documentation not ready - wait for it (with timeout)
                            CompletableFuture<String> future = generationFutures.get(program);
                            if (future == null) {
                                // Not generating yet - start generation and wait
                                future = generateDocumentationAsync(program);
                            }
                            
                            try {
                                // Block and wait for documentation (with timeout)
                                cachedDoc = future.get(GENERATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                                programDocumentationCache.put(program, cachedDoc);
                            } catch (TimeoutException e) {
                                logError("Timeout waiting for documentation generation for " + program.getName());
                                ObjectNode errorResult = JSON.createObjectNode();
                                errorResult.put("name", program.getName());
                                errorResult.put("path", program.getDomainFile().getPathname());
                                errorResult.put("error", "Documentation generation timed out after " + GENERATION_TIMEOUT_SECONDS + " seconds");
                                cachedDoc = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                                programDocumentationCache.put(program, cachedDoc);
                            } catch (Exception e) {
                                logError("Error waiting for documentation generation for " + program.getName(), e);
                                ObjectNode errorResult = JSON.createObjectNode();
                                errorResult.put("name", program.getName());
                                errorResult.put("path", program.getDomainFile().getPathname());
                                errorResult.put("error", "Error generating documentation: " + e.getMessage());
                                cachedDoc = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                                programDocumentationCache.put(program, cachedDoc);
                            }
                        }
                    }

                    // Build complete JSON documentation from all cached program docs
                    ObjectNode root = JSON.createObjectNode();
                    ArrayNode programsArray = root.putArray("programs");
                    
                    for (Program program : openPrograms) {
                        logInfo("=== DIAGNOSTIC: Building final JSON for program: " + program.getName() + " ===");
                        String cachedDoc = programDocumentationCache.get(program);
                        logInfo("Cached doc for final build - exists: " + (cachedDoc != null) + 
                                ", length: " + (cachedDoc != null ? cachedDoc.length() : 0));
                        if (cachedDoc != null) {
                            // DIAGNOSTIC: Log first 500 chars of cached doc
                            String preview = cachedDoc.length() > 500 ? cachedDoc.substring(0, 500) + "..." : cachedDoc;
                            logInfo("Cached doc preview: " + preview);
                            
                            try {
                                // Parse cached JSON and add to programs array
                                ObjectNode programDoc = (ObjectNode) JSON.readTree(cachedDoc);
                                List<String> keys = new ArrayList<>();
                                programDoc.fieldNames().forEachRemaining(keys::add);
                                logInfo("Successfully parsed JSON, keys: " + String.join(", ", keys));
                                programsArray.add(programDoc);
                                logInfo("Added program doc to array, array size now: " + programsArray.size());
                            } catch (Exception e) {
                                logError("Error parsing cached documentation for " + program.getName(), e);
                                logError("Failed JSON content (first 1000 chars): " + 
                                        (cachedDoc.length() > 1000 ? cachedDoc.substring(0, 1000) : cachedDoc));
                                // Add error entry
                                ObjectNode errorEntry = JSON.createObjectNode();
                                errorEntry.put("name", program.getName());
                                errorEntry.put("path", program.getDomainFile().getPathname());
                                errorEntry.put("error", "Error parsing cached documentation: " + e.getMessage());
                                programsArray.add(errorEntry);
                            }
                        } else {
                            logError("WARNING: No cached doc found for program: " + program.getName());
                        }
                    }
                    
            root.put("totalPrograms", programsArray.size());
            root.put("generatedAt", System.currentTimeMillis());
            
                    // DIAGNOSTIC: Log final root structure
                    logInfo("=== DIAGNOSTIC: Final root JSON structure ===");
                    logInfo("totalPrograms: " + programsArray.size());
                    logInfo("programs array size: " + programsArray.size());
                    String rootPreview = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root);
                    logInfo("Root JSON preview (first 1000 chars): " + 
                            (rootPreview.length() > 1000 ? rootPreview.substring(0, 1000) + "..." : rootPreview));

                    // Update full cache
                    try {
                        cachedFullDocumentation = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root);
                        logInfo("=== DIAGNOSTIC: Final cached documentation length: " + cachedFullDocumentation.length() + " ===");
                    } catch (JsonProcessingException e) {
                        logError("Error serializing full documentation", e);
                        ObjectNode errorResult = JSON.createObjectNode();
                        errorResult.put("error", "Error serializing documentation: " + e.getMessage());
                        try {
                            cachedFullDocumentation = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                        } catch (JsonProcessingException e2) {
                            cachedFullDocumentation = "{\"error\":\"Failed to serialize error message\"}";
                        }
                    }
                    cacheTimestamp = now;

                    TextResourceContents content = new TextResourceContents(
                        RESOURCE_ID,
                        RESOURCE_MIME_TYPE,
                        cachedFullDocumentation
                    );
                    resourceContents.add(content);

                } catch (Exception e) {
                    logError("Error generating program documentation resource", e);
                    ObjectNode errorResult = JSON.createObjectNode();
                    errorResult.put("error", "Error generating documentation: " + e.getMessage());
                    String errorJson;
                    try {
                        errorJson = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                    } catch (JsonProcessingException jsonEx) {
                        errorJson = "{\"error\":\"Failed to serialize error message\"}";
                    }
                    TextResourceContents errorContent = new TextResourceContents(
                        RESOURCE_ID,
                        RESOURCE_MIME_TYPE,
                        errorJson
                    );
                    resourceContents.add(errorContent);
                }

                return new ReadResourceResult(resourceContents);
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
        
        // Pre-generate documentation for all currently open programs on startup
        // This ensures documentation is ready immediately when requested
        pregenerateDocumentationForOpenPrograms();
    }
    
    /**
     * Pre-generate documentation for all currently open programs.
     * Called during resource registration to ensure documentation is ready immediately.
     */
    private void pregenerateDocumentationForOpenPrograms() {
        try {
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            if (openPrograms.isEmpty()) {
                logInfo("No programs currently open - documentation will be generated when programs are opened");
                return;
            }
            
            logInfo("Pre-generating comprehensive documentation for " + openPrograms.size() + " open program(s)");
            for (Program program : openPrograms) {
                // Generate synchronously during startup to ensure it's ready
                // This happens once during server initialization, so blocking is acceptable
                if (!programDocumentationCache.containsKey(program)) {
                    try {
                        String doc = generateProgramDocumentation(program);
                        programDocumentationCache.put(program, doc);
                        logInfo("Pre-generated comprehensive documentation for: " + program.getName());
                    } catch (Exception e) {
                        logError("Failed to pre-generate documentation for " + program.getName(), e);
                        ObjectNode errorResult = JSON.createObjectNode();
                        errorResult.put("name", program.getName());
                        errorResult.put("path", program.getDomainFile().getPathname());
                        errorResult.put("error", "Error generating documentation: " + e.getMessage());
                        String errorJson = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                        programDocumentationCache.put(program, errorJson);
                    }
                }
            }
            
            // Build initial full cache
            rebuildFullCache();
            logInfo("Comprehensive documentation pre-generation complete");
        } catch (Exception e) {
            logError("Error during documentation pre-generation", e);
        }
    }

    /**
     * Generates comprehensive JSON documentation for a single program.
     * Collects ALL data: functions, comments, symbols, bookmarks, strings, data types, etc.
     */
    private String generateProgramDocumentation(Program program) {
        logInfo("=== DIAGNOSTIC: Starting documentation generation for: " + program.getName() + " ===");
        logInfo("Program path: " + program.getDomainFile().getPathname());
        logInfo("Program closed: " + program.isClosed());
        
        ObjectNode programDoc = JSON.createObjectNode();
        
        // Basic program information
        programDoc.put("name", program.getName());
        programDoc.put("path", program.getDomainFile().getPathname());
        logInfo("Added basic info: name=" + program.getName() + ", path=" + program.getDomainFile().getPathname());
        programDoc.put("executableFormat", program.getExecutableFormat());
        if (program.getCreationDate() != null) {
            programDoc.put("creationDate", program.getCreationDate().toString());
        }
        programDoc.put("modificationNumber", program.getModificationNumber());
        
        // Language and compiler information
        Language language = program.getLanguage();
        CompilerSpec compilerSpec = program.getCompilerSpec();
        ObjectNode languageInfo = JSON.createObjectNode();
        languageInfo.put("id", language.getLanguageID().getIdAsString());
        languageInfo.put("version", language.getVersion());
        languageInfo.put("compilerSpec", compilerSpec.getCompilerSpecID().getIdAsString());
        languageInfo.put("endianness", language.isBigEndian() ? "big" : "little");
        languageInfo.put("addressSize", language.getDefaultSpace().getSize());
        programDoc.set("language", languageInfo);
        
        // Memory layout
        Memory memory = program.getMemory();
        ArrayNode memoryBlocks = programDoc.putArray("memoryBlocks");
        MemoryBlock[] blocks = memory.getBlocks();
        for (MemoryBlock block : blocks) {
            ObjectNode blockInfo = JSON.createObjectNode();
            blockInfo.put("name", block.getName());
            blockInfo.put("startAddress", AddressUtil.formatAddress(block.getStart()));
            blockInfo.put("endAddress", AddressUtil.formatAddress(block.getEnd()));
            blockInfo.put("size", block.getSize());
            blockInfo.put("readable", block.isRead());
            blockInfo.put("writable", block.isWrite());
            blockInfo.put("executable", block.isExecute());
            memoryBlocks.add(blockInfo);
        }
        programDoc.put("totalMemorySize", memory.getSize());
        
        // Collect ALL functions with comprehensive details
        ArrayNode functions = programDoc.putArray("functions");
        FunctionManager functionManager = program.getFunctionManager();
        logInfo("FunctionManager.getFunctionCount(): " + functionManager.getFunctionCount());
        FunctionIterator funcIter = functionManager.getFunctions(true);
        int funcCount = 0;
        while (funcIter.hasNext()) {
            Function function = funcIter.next();
            functions.add(collectFunctionData(program, function));
            funcCount++;
            if (funcCount % 100 == 0) {
                logInfo("Collected " + funcCount + " functions so far...");
            }
        }
        logInfo("Total functions collected: " + funcCount);
        programDoc.put("functionCount", functionManager.getFunctionCount());
        
        // Collect ALL comments (all types, all addresses)
        ArrayNode comments = programDoc.putArray("comments");
        collectAllComments(program, comments);
        
        // Collect ALL symbols/labels
        ArrayNode symbols = programDoc.putArray("symbols");
        collectAllSymbols(program, symbols);
        
        // Collect ALL bookmarks
        ArrayNode bookmarks = programDoc.putArray("bookmarks");
        collectAllBookmarks(program, bookmarks);
        
        // Collect ALL strings
        ArrayNode strings = programDoc.putArray("strings");
        collectAllStrings(program, strings);
        
        // Collect ALL data types and structures
        ArrayNode dataTypes = programDoc.putArray("dataTypes");
        ArrayNode structures = programDoc.putArray("structures");
        collectAllDataTypes(program, dataTypes, structures);
        
        // Collect imports and exports
        ObjectNode importsExports = JSON.createObjectNode();
        collectImportsExports(program, importsExports);
        programDoc.set("importsExports", importsExports);
        
        // Collect function tags
        ArrayNode functionTags = programDoc.putArray("functionTags");
        collectFunctionTags(program, functionTags);
        
        // Statistics
        ObjectNode statistics = JSON.createObjectNode();
        statistics.put("totalFunctions", functionManager.getFunctionCount());
        statistics.put("totalSymbols", program.getSymbolTable().getNumSymbols());
        statistics.put("totalComments", comments.size());
        statistics.put("totalBookmarks", bookmarks.size());
        statistics.put("totalStrings", strings.size());
        statistics.put("totalDataTypes", dataTypes.size());
        statistics.put("totalStructures", structures.size());
        programDoc.set("statistics", statistics);
        
        logInfo("=== DIAGNOSTIC: Documentation generation complete ===");
        logInfo("Statistics: functions=" + functions.size() + 
                ", comments=" + comments.size() + 
                ", symbols=" + symbols.size() + 
                ", bookmarks=" + bookmarks.size() + 
                ", strings=" + strings.size());
        
        try {
            String result = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(programDoc);
            logInfo("Final JSON length: " + result.length());
            return result;
        } catch (JsonProcessingException e) {
            logError("Error serializing program documentation to JSON", e);
            ObjectNode errorResult = JSON.createObjectNode();
            errorResult.put("name", program.getName());
            errorResult.put("path", program.getDomainFile().getPathname());
            errorResult.put("error", "Error serializing documentation: " + e.getMessage());
            try {
                return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
            } catch (JsonProcessingException e2) {
                return "{\"error\":\"Failed to serialize error message\"}";
            }
        }
    }
    
    /**
     * Collect comprehensive function data including parameters, variables, tags, and comments.
     */
    private ObjectNode collectFunctionData(Program program, Function function) {
        ObjectNode funcData = JSON.createObjectNode();
        
        funcData.put("name", function.getName());
        funcData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        funcData.put("signature", function.getSignature().toString());
        funcData.put("callingConvention", function.getCallingConventionName());
        funcData.put("returnType", function.getReturnType().getDisplayName());
        funcData.put("hasCustomStorage", function.hasCustomVariableStorage());
        funcData.put("hasVarArgs", function.hasVarArgs());
        funcData.put("isInline", function.isInline());
        funcData.put("isNoReturn", function.hasNoReturn());
        funcData.put("isThunk", function.isThunk());
        if (function.getThunkedFunction(false) != null) {
            funcData.put("thunkedFunction", function.getThunkedFunction(false).getName());
        }
        
        // Parameters
        ArrayNode parameters = funcData.putArray("parameters");
        ParameterDefinition[] params = function.getSignature().getArguments();
        for (ParameterDefinition param : params) {
            ObjectNode paramData = JSON.createObjectNode();
            paramData.put("name", param.getName());
            paramData.put("type", param.getDataType().getDisplayName());
            paramData.put("ordinal", param.getOrdinal());
            parameters.add(paramData);
        }
        
        // Local variables
        ArrayNode variables = funcData.putArray("variables");
        Variable[] vars = function.getAllVariables();
        for (Variable var : vars) {
            ObjectNode varData = JSON.createObjectNode();
            varData.put("name", var.getName());
            varData.put("type", var.getDataType().getDisplayName());
            varData.put("address", AddressUtil.formatAddress(var.getMinAddress()));
            varData.put("storage", var.getVariableStorage().toString());
            variables.add(varData);
        }
        
        // Function tags
        ArrayNode tags = funcData.putArray("tags");
        Set<FunctionTag> functionTags = function.getTags();
        for (FunctionTag tag : functionTags) {
            tags.add(tag.getName());
        }
        
        // Function comment
        String comment = function.getComment();
        if (comment != null && !comment.isEmpty()) {
            funcData.put("comment", comment);
        }
        
        // Body address range
        AddressSetView body = function.getBody();
        if (body != null && !body.isEmpty()) {
            funcData.put("startAddress", AddressUtil.formatAddress(body.getMinAddress()));
            funcData.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
        }
        
        return funcData;
    }
    
    /**
     * Collect ALL comments of ALL types from the entire program.
     */
    private void collectAllComments(Program program, ArrayNode comments) {
        Listing listing = program.getListing();
        CodeUnitIterator codeUnits = listing.getCodeUnits(true);
        
        Map<String, CommentType> commentTypeMap = Map.of(
            "pre", CommentType.PRE,
            "eol", CommentType.EOL,
            "post", CommentType.POST,
            "plate", CommentType.PLATE,
            "repeatable", CommentType.REPEATABLE
        );
        
        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            Address addr = cu.getAddress();
            
            for (Map.Entry<String, CommentType> entry : commentTypeMap.entrySet()) {
                String comment = cu.getComment(entry.getValue());
                if (comment != null && !comment.isEmpty()) {
                    ObjectNode commentData = JSON.createObjectNode();
                    commentData.put("address", AddressUtil.formatAddress(addr));
                    commentData.put("type", entry.getKey());
                    commentData.put("text", comment);
                    comments.add(commentData);
                }
            }
        }
    }
    
    /**
     * Collect ALL symbols/labels from the program.
     */
    private void collectAllSymbols(Program program, ArrayNode symbols) {
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
        
        while (symbolIter.hasNext()) {
            Symbol symbol = symbolIter.next();
            ObjectNode symbolData = JSON.createObjectNode();
            symbolData.put("name", symbol.getName());
            symbolData.put("address", AddressUtil.formatAddress(symbol.getAddress()));
            symbolData.put("type", symbol.getSymbolType().toString());
            symbolData.put("isPrimary", symbol.isPrimary());
            symbolData.put("isExternal", symbol.isExternal());
            
            Namespace namespace = symbol.getParentNamespace();
            if (namespace != null && !namespace.isGlobal()) {
                symbolData.put("namespace", namespace.getName(true));
            }
            
            // Symbol source information
            symbolData.put("source", symbol.getSource().toString());
            
            symbols.add(symbolData);
        }
    }
    
    /**
     * Collect ALL bookmarks from the program.
     */
    private void collectAllBookmarks(Program program, ArrayNode bookmarks) {
        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        Iterator<Bookmark> bookmarkIter = bookmarkMgr.getBookmarksIterator();
        
        while (bookmarkIter.hasNext()) {
            Bookmark bookmark = bookmarkIter.next();
            ObjectNode bookmarkData = JSON.createObjectNode();
            bookmarkData.put("address", AddressUtil.formatAddress(bookmark.getAddress()));
            bookmarkData.put("type", bookmark.getType().getTypeString());
            bookmarkData.put("category", bookmark.getCategory());
            bookmarkData.put("comment", bookmark.getComment());
            bookmarks.add(bookmarkData);
        }
    }
    
    /**
     * Collect ALL strings from the program.
     */
    private void collectAllStrings(Program program, ArrayNode strings) {
        DataIterator dataIterator = program.getListing().getDefinedData(true);
        
        for (Data data : dataIterator) {
            if (data.getValue() instanceof String) {
                String stringValue = (String) data.getValue();
                ObjectNode stringData = JSON.createObjectNode();
                stringData.put("address", AddressUtil.formatAddress(data.getAddress()));
                stringData.put("content", stringValue);
                stringData.put("length", stringValue.length());
                stringData.put("dataType", data.getDataType().getName());
                strings.add(stringData);
            }
        }
    }
    
    /**
     * Collect ALL data types and structures from the program.
     */
    private void collectAllDataTypes(Program program, ArrayNode dataTypes, ArrayNode structures) {
        DataTypeManager dtm = program.getDataTypeManager();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        
        while (iter.hasNext()) {
            DataType dt = iter.next();
            
            // Add to data types
            ObjectNode typeData = JSON.createObjectNode();
            typeData.put("name", dt.getName());
            typeData.put("displayName", dt.getDisplayName());
            typeData.put("category", dt.getCategoryPath().toString());
            typeData.put("length", dt.getLength());
            dataTypes.add(typeData);
            
            // If it's a structure/union, add detailed info
            if (dt instanceof Composite) {
                Composite composite = (Composite) dt;
                ObjectNode structData = JSON.createObjectNode();
                structData.put("name", composite.getName());
                structData.put("displayName", composite.getDisplayName());
                structData.put("category", composite.getCategoryPath().toString());
                structData.put("length", composite.getLength());
                structData.put("isUnion", dt instanceof Union);
                
                if (dt instanceof Structure) {
                    Structure struct = (Structure) dt;
                    structData.put("isPacked", struct.isPackingEnabled());
                }
                
                ArrayNode fields = structData.putArray("fields");
                for (int i = 0; i < composite.getNumComponents(); i++) {
                    DataTypeComponent component = composite.getComponent(i);
                    ObjectNode fieldData = JSON.createObjectNode();
                    fieldData.put("name", component.getFieldName());
                    fieldData.put("type", component.getDataType().getDisplayName());
                    fieldData.put("offset", component.getOffset());
                    fieldData.put("length", component.getLength());
                    String comment = component.getComment();
                    if (comment != null && !comment.isEmpty()) {
                        fieldData.put("comment", comment);
                    }
                    fields.add(fieldData);
                }
                
                structures.add(structData);
            }
        }
    }
    
    /**
     * Collect imports and exports from the program.
     */
    private void collectImportsExports(Program program, ObjectNode importsExports) {
        try {
            // Collect imports from external functions
            ArrayNode imports = importsExports.putArray("imports");
            FunctionManager functionManager = program.getFunctionManager();
            FunctionIterator externalFunctions = functionManager.getExternalFunctions();
            
            Map<String, List<ObjectNode>> importsByLibrary = new HashMap<>();
            while (externalFunctions.hasNext()) {
                Function func = externalFunctions.next();
                ExternalLocation extLoc = func.getExternalLocation();
                if (extLoc != null) {
                    String libraryName = extLoc.getLibraryName();
                    if (libraryName == null || libraryName.isEmpty()) {
                        libraryName = "UNKNOWN";
                    }
                    
                    ObjectNode importData = JSON.createObjectNode();
                    importData.put("name", func.getName());
                    importData.put("address", AddressUtil.formatAddress(func.getEntryPoint()));
                    importData.put("library", libraryName);
                    importData.put("type", "FUNCTION");
                    
                    String originalName = extLoc.getOriginalImportedName();
                    if (originalName != null && !originalName.equals(func.getName())) {
                        importData.put("originalName", originalName);
                    }
                    
                    importsByLibrary.computeIfAbsent(libraryName, k -> new ArrayList<>()).add(importData);
                }
            }
            
            // Add imports grouped by library
            for (Map.Entry<String, List<ObjectNode>> entry : importsByLibrary.entrySet()) {
                ObjectNode libraryGroup = JSON.createObjectNode();
                libraryGroup.put("library", entry.getKey());
                ArrayNode libraryImports = libraryGroup.putArray("symbols");
                for (ObjectNode importData : entry.getValue()) {
                    libraryImports.add(importData);
                }
                imports.add(libraryGroup);
            }
            
            // Collect exports (entry points)
            ArrayNode exports = importsExports.putArray("exports");
            SymbolTable symbolTable = program.getSymbolTable();
            ghidra.program.model.address.AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
            while (entryPoints.hasNext()) {
                Address entryPoint = entryPoints.next();
                Symbol[] symbols = symbolTable.getSymbols(entryPoint);
                if (symbols.length > 0) {
                    Symbol symbol = symbols[0];
                    ObjectNode exportData = JSON.createObjectNode();
                    exportData.put("name", symbol.getName());
                    exportData.put("address", AddressUtil.formatAddress(entryPoint));
                    exportData.put("type", symbol.getSymbolType().toString());
                    exports.add(exportData);
                }
            }
            
        } catch (Exception e) {
            logError("Error collecting imports/exports", e);
            importsExports.put("error", "Error collecting imports/exports: " + e.getMessage());
        }
    }
    
    /**
     * Collect ALL function tags defined in the program.
     */
    private void collectFunctionTags(Program program, ArrayNode functionTags) {
        FunctionTagManager tagManager = program.getFunctionManager().getFunctionTagManager();
        List<? extends FunctionTag> allTags = tagManager.getAllFunctionTags();
        
        for (FunctionTag tag : allTags) {
            ObjectNode tagData = JSON.createObjectNode();
            tagData.put("name", tag.getName());
            String comment = tag.getComment();
            if (comment != null && !comment.isEmpty()) {
                tagData.put("comment", comment);
            }
            functionTags.add(tagData);
        }
    }

    /**
     * Generate documentation for a program asynchronously.
     * Returns a CompletableFuture that completes when documentation is ready.
     * If generation is already in progress, returns the existing future.
     */
    private CompletableFuture<String> generateDocumentationAsync(Program program) {
        // Check if generation is already in progress
        CompletableFuture<String> existingFuture = generationFutures.get(program);
        if (existingFuture != null && !existingFuture.isDone()) {
            return existingFuture; // Already generating
        }

        // Create new future for this generation
        CompletableFuture<String> future = new CompletableFuture<>();
        CompletableFuture<String> previous = generationFutures.putIfAbsent(program, future);
        if (previous != null && !previous.isDone()) {
            return previous; // Another thread started generation
        }

        // Get thread pool from service registry
        GThreadPool threadPool = RevaInternalServiceRegistry.getService(GThreadPool.class);

        if (threadPool == null) {
            // Fallback: generate synchronously if no thread pool available
            try {
                String doc = generateProgramDocumentation(program);
                programDocumentationCache.put(program, doc);
                future.complete(doc);
                invalidateFullCache();
            } catch (Exception e) {
                logError("Error generating documentation for " + program.getName(), e);
                ObjectNode errorResult = JSON.createObjectNode();
                errorResult.put("name", program.getName());
                errorResult.put("path", program.getDomainFile().getPathname());
                errorResult.put("error", "Error generating documentation: " + e.getMessage());
                try {
                    String errorJson = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                    programDocumentationCache.put(program, errorJson);
                    future.complete(errorJson);
                } catch (Exception jsonEx) {
                    future.completeExceptionally(jsonEx);
                }
                invalidateFullCache();
            }
            return future;
        }

        // Generate in background thread
        threadPool.submit(() -> {
            try {
                String doc = generateProgramDocumentation(program);
                programDocumentationCache.put(program, doc);
                future.complete(doc);
                invalidateFullCache(); // Invalidate full cache so it gets regenerated with new program doc
            } catch (Exception e) {
                logError("Error generating documentation for " + program.getName(), e);
                ObjectNode errorResult = JSON.createObjectNode();
                errorResult.put("name", program.getName());
                errorResult.put("path", program.getDomainFile().getPathname());
                errorResult.put("error", "Error generating documentation: " + e.getMessage());
                try {
                    String errorJson = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(errorResult);
                    programDocumentationCache.put(program, errorJson);
                    future.complete(errorJson);
                } catch (Exception jsonEx) {
                    future.completeExceptionally(jsonEx);
                }
                invalidateFullCache();
            } finally {
                // Remove future from map once complete (but keep cache entry)
                generationFutures.remove(program, future);
            }
        });

        return future;
    }
    
    /**
     * Rebuild the full documentation cache from all cached program docs.
     */
    private void rebuildFullCache() {
        try {
            List<Program> openPrograms = RevaProgramManager.getOpenPrograms();
            if (openPrograms.isEmpty()) {
                ObjectNode emptyResult = JSON.createObjectNode();
                emptyResult.put("programs", JSON.createArrayNode());
                emptyResult.put("message", "No programs are currently open");
                cachedFullDocumentation = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(emptyResult);
                cacheTimestamp = System.currentTimeMillis();
                return;
            }

            ObjectNode root = JSON.createObjectNode();
            ArrayNode programsArray = root.putArray("programs");
            
            for (Program program : openPrograms) {
                String cachedDoc = programDocumentationCache.get(program);
                if (cachedDoc != null) {
                    try {
                        ObjectNode programDoc = (ObjectNode) JSON.readTree(cachedDoc);
                        programsArray.add(programDoc);
                    } catch (Exception e) {
                        logError("Error parsing cached documentation for " + program.getName(), e);
                    }
                }
            }
            
            root.put("totalPrograms", programsArray.size());
            root.put("generatedAt", System.currentTimeMillis());

            cachedFullDocumentation = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(root);
            cacheTimestamp = System.currentTimeMillis();
        } catch (Exception e) {
            logError("Error rebuilding full documentation cache", e);
        }
    }

    /**
     * Invalidate the full documentation cache so it gets regenerated.
     */
    private void invalidateFullCache() {
        cachedFullDocumentation = null;
    }

    @Override
    public void programOpened(Program program) {
        // Remove old cache entry and any pending futures
        programDocumentationCache.remove(program);
        CompletableFuture<String> future = generationFutures.remove(program);
        if (future != null && !future.isDone()) {
            future.cancel(true);
        }
        invalidateFullCache();
        
        // Generate documentation immediately (asynchronously, but caller can wait if needed)
        generateDocumentationAsync(program);
    }

    @Override
    public void programClosed(Program program) {
        // Remove from cache and cancel any pending generation when program closes
        programDocumentationCache.remove(program);
        CompletableFuture<String> future = generationFutures.remove(program);
        if (future != null && !future.isDone()) {
            future.cancel(true);
        }
        invalidateFullCache();
        rebuildFullCache(); // Rebuild cache without the closed program
    }
}
