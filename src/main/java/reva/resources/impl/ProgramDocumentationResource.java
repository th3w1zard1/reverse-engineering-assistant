package reva.resources.impl;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;
import io.modelcontextprotocol.server.McpServerFeatures.SyncResourceSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceContents;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import reva.plugin.RevaProgramManager;
import reva.resources.AbstractResourceProvider;
import reva.util.RevaInternalServiceRegistry;
import generic.concurrent.GThreadPool;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resource provider for program documentation.
 * Provides comprehensive information about the currently open programs.
 * Uses caching to improve performance - documentation is regenerated only when programs change.
 */
public class ProgramDocumentationResource extends AbstractResourceProvider {
    private static final String RESOURCE_ID = "ghidra://program-documentation";
    private static final String RESOURCE_NAME = "program-documentation";
    private static final String RESOURCE_DESCRIPTION = "Documentation and metadata for all open programs";
    private static final String RESOURCE_MIME_TYPE = "text/markdown";

    // Cache documentation per program to avoid regenerating on every request
    private final Map<Program, String> programDocumentationCache = new ConcurrentHashMap<>();
    // Track programs currently being generated to avoid duplicate work
    private final Map<Program, Boolean> generationInProgress = new ConcurrentHashMap<>();
    private volatile String cachedFullDocumentation = null;
    private volatile long cacheTimestamp = 0;
    private static final long CACHE_VALIDITY_MS = 30000; // Cache for 30 seconds (longer since we pre-generate)

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

                    if (openPrograms.isEmpty()) {
                        String emptyText = "# Program Documentation\n\nNo programs are currently open.";
                        TextResourceContents emptyContent = new TextResourceContents(
                            RESOURCE_ID,
                            RESOURCE_MIME_TYPE,
                            emptyText
                        );
                        resourceContents.add(emptyContent);
                        cachedFullDocumentation = emptyText;
                        cacheTimestamp = now;
                        return new ReadResourceResult(resourceContents);
                    }

                    // Build documentation using cached per-program docs where possible
                    StringBuilder documentation = new StringBuilder();
                    documentation.append("# Program Documentation\n\n");
                    documentation.append("This document provides comprehensive information about all currently open programs.\n\n");

                    boolean cacheInvalidated = false;
                    boolean hasMissingDocs = false;
                    for (Program program : openPrograms) {
                        String cachedDoc = programDocumentationCache.get(program);
                        if (cachedDoc == null) {
                            // If not cached, trigger background generation and show placeholder
                            hasMissingDocs = true;
                            cachedDoc = "## " + program.getName() + "\n\n*Documentation is being generated in the background...*\n\n";
                            // Trigger background generation if not already in progress
                            if (!generationInProgress.containsKey(program)) {
                                generateDocumentationInBackground(program);
                            }
                        }
                        documentation.append(cachedDoc);
                        documentation.append("\n\n---\n\n");
                    }

                    // If we have all cached docs, update full cache
                    if (!hasMissingDocs) {
                        cachedFullDocumentation = documentation.toString();
                        cacheTimestamp = now;
                    } else {
                        // If some docs are missing, trigger background generation for all missing
                        for (Program program : openPrograms) {
                            if (!programDocumentationCache.containsKey(program) && !generationInProgress.containsKey(program)) {
                                generateDocumentationInBackground(program);
                            }
                        }
                    }

                    TextResourceContents content = new TextResourceContents(
                        RESOURCE_ID,
                        RESOURCE_MIME_TYPE,
                        documentation.toString()
                    );
                    resourceContents.add(content);

                } catch (Exception e) {
                    TextResourceContents errorContent = new TextResourceContents(
                        RESOURCE_ID,
                        RESOURCE_MIME_TYPE,
                        "# Program Documentation\n\nError generating documentation: " + e.getMessage()
                    );
                    resourceContents.add(errorContent);
                }

                return new ReadResourceResult(resourceContents);
            }
        );

        server.addResource(resourceSpec);
        logInfo("Registered resource: " + RESOURCE_NAME);
    }

    /**
     * Generates markdown documentation for a single program.
     * Optimized to minimize expensive API calls.
     */
    private String generateProgramDocumentation(Program program) {
        StringBuilder doc = new StringBuilder();

        // Program basic information
        doc.append("## ").append(program.getName()).append("\n\n");
        doc.append("**Path:** `").append(program.getDomainFile().getPathname()).append("`\n\n");

        // Language and compiler information (cached by Ghidra, fast)
        Language language = program.getLanguage();
        CompilerSpec compilerSpec = program.getCompilerSpec();
        doc.append("### Language & Compiler\n\n");
        doc.append("- **Language ID:** ").append(language.getLanguageID().getIdAsString()).append("\n");
        doc.append("- **Language Version:** ").append(language.getVersion()).append("\n");
        doc.append("- **Compiler Spec:** ").append(compilerSpec.getCompilerSpecID().getIdAsString()).append("\n");
        doc.append("- **Endianness:** ").append(language.isBigEndian() ? "Big Endian" : "Little Endian").append("\n");
        doc.append("- **Address Size:** ").append(language.getDefaultSpace().getSize()).append(" bits\n\n");

        // Memory information (optimized - get blocks once)
        Memory memory = program.getMemory();
        doc.append("### Memory Layout\n\n");
        MemoryBlock[] blocks = memory.getBlocks();
        doc.append("**Total Blocks:** ").append(blocks.length).append("\n\n");
        
        // Only show table if reasonable number of blocks (avoid huge tables)
        if (blocks.length <= 50) {
            doc.append("| Block Name | Start Address | End Address | Size | Read | Write | Execute |\n");
            doc.append("|-----------|---------------|-------------|------|------|-------|----------|\n");
            for (MemoryBlock block : blocks) {
                doc.append("| ").append(block.getName()).append(" | ");
                doc.append("`").append(block.getStart().toString()).append("` | ");
                doc.append("`").append(block.getEnd().toString()).append("` | ");
                doc.append(formatSize(block.getSize())).append(" | ");
                doc.append(block.isRead() ? "✓" : "✗").append(" | ");
                doc.append(block.isWrite() ? "✓" : "✗").append(" | ");
                doc.append(block.isExecute() ? "✓" : "✗").append(" |\n");
            }
            doc.append("\n");
        } else {
            // For programs with many blocks, just show summary
            doc.append("_(").append(blocks.length).append(" memory blocks - too many to display in table)_\n\n");
        }

        // Function and symbol statistics (these are fast - just counts)
        FunctionManager functionManager = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();
        doc.append("### Analysis Statistics\n\n");
        doc.append("- **Total Functions:** ").append(functionManager.getFunctionCount()).append("\n");
        doc.append("- **Total Symbols:** ").append(symbolTable.getNumSymbols()).append("\n");
        doc.append("- **Program Size:** ").append(formatSize(memory.getSize())).append("\n\n");

        // Program metadata (cached, fast)
        doc.append("### Program Metadata\n\n");
        doc.append("- **Executable Format:** ").append(program.getExecutableFormat()).append("\n");
        if (program.getCreationDate() != null) {
            doc.append("- **Creation Date:** ").append(program.getCreationDate().toString()).append("\n");
        }
        // Modification number is available but not a date
        doc.append("- **Modification Number:** ").append(program.getModificationNumber()).append("\n");

        return doc.toString();
    }

    /**
     * Formats a size in bytes to a human-readable string.
     */
    private String formatSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
        } else {
            return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        }
    }

    /**
     * Generate documentation for a program in the background using Ghidra's thread pool.
     */
    private void generateDocumentationInBackground(Program program) {
        // Mark as in progress to avoid duplicate work
        if (generationInProgress.putIfAbsent(program, true) != null) {
            return; // Already generating
        }

        // Get thread pool from service registry
        GThreadPool threadPool = RevaInternalServiceRegistry.getService(GThreadPool.class);

        if (threadPool == null) {
            // Fallback: generate synchronously if no thread pool available
            generationInProgress.remove(program);
            try {
                String doc = generateProgramDocumentation(program);
                programDocumentationCache.put(program, doc);
                invalidateFullCache();
            } catch (Exception e) {
                programDocumentationCache.put(program, 
                    "## Error generating documentation for program\n\nError: " + e.getMessage() + "\n\n");
            }
            return;
        }

        // Generate in background thread
        threadPool.submit(() -> {
            try {
                String doc = generateProgramDocumentation(program);
                programDocumentationCache.put(program, doc);
                invalidateFullCache(); // Invalidate full cache so it gets regenerated with new program doc
            } catch (Exception e) {
                programDocumentationCache.put(program, 
                    "## Error generating documentation for program\n\nError: " + e.getMessage() + "\n\n");
                invalidateFullCache();
            } finally {
                generationInProgress.remove(program);
            }
        });
    }

    /**
     * Invalidate the full documentation cache so it gets regenerated.
     */
    private void invalidateFullCache() {
        cachedFullDocumentation = null;
    }

    @Override
    public void programOpened(Program program) {
        // Remove old cache entry and trigger background generation
        programDocumentationCache.remove(program);
        generationInProgress.remove(program);
        invalidateFullCache();
        
        // Generate documentation in background immediately
        generateDocumentationInBackground(program);
    }

    @Override
    public void programClosed(Program program) {
        // Remove from cache when program closes
        programDocumentationCache.remove(program);
        generationInProgress.remove(program);
        invalidateFullCache();
    }
}
