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
package reva.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;

/**
 * Utility for intelligent automatic bookmarking of frequently referenced addresses.
 *
 * This utility tracks address access frequency and automatically creates bookmarks
 * when addresses exceed a percentile-based threshold (top 2-5% by reference count).
 * This helps identify important locations in the binary that are referenced multiple times.
 *
 * The bookmarking is intelligent in that it:
 * - Only bookmarks addresses that are actually referenced (not just accessed)
 * - Uses percentile-based thresholds to bookmark only the top 2-5% of addresses
 * - Uses appropriate bookmark types based on context (function entry points, data, etc.)
 * - Avoids duplicate bookmarks
 * - Respects existing bookmarks
 */
public class IntelligentBookmarkUtil {

    /** Default percentile: bookmark top 3% (97th percentile) */
    private static final double DEFAULT_PERCENTILE = 97.0;

    /** Minimum percentile to prevent bookmarking too many addresses */
    private static final double MIN_PERCENTILE = 95.0;

    /** Maximum percentile to ensure some addresses are bookmarked */
    private static final double MAX_PERCENTILE = 99.0;

    /** Per-program percentile thresholds (cached to avoid recalculation) */
    private static final Map<String, Integer> programPercentileThresholds = new ConcurrentHashMap<>();

    /** Per-program reference count distributions (cached) */
    private static final Map<String, List<Integer>> programReferenceCounts = new ConcurrentHashMap<>();

    /**
     * Check if an address should be automatically bookmarked based on reference count.
     * Uses percentile-based threshold to bookmark only the top 2-5% of addresses.
     * If the address exceeds the percentile threshold, creates a bookmark automatically.
     *
     * @param program The program
     * @param address The address to check
     * @param percentile Percentile threshold (95.0-99.0, defaults to DEFAULT_PERCENTILE if <= 0)
     * @return true if a bookmark was created, false otherwise
     */
    public static boolean checkAndBookmarkIfFrequent(Program program, Address address, double percentile) {
        if (program == null || address == null) {
            return false;
        }

        // Use default percentile if invalid
        if (percentile <= 0) {
            percentile = DEFAULT_PERCENTILE;
        }
        percentile = Math.max(MIN_PERCENTILE, Math.min(MAX_PERCENTILE, percentile));

        // Get or calculate percentile threshold for this program
        String programPath = program.getDomainFile().getPathname();
        Integer threshold = programPercentileThresholds.get(programPath);
        
        if (threshold == null) {
            // Calculate percentile threshold by collecting all reference counts
            threshold = calculatePercentileThreshold(program, percentile);
            if (threshold == null) {
                // If calculation failed, don't bookmark anything
                return false;
            }
            programPercentileThresholds.put(programPath, threshold);
            Msg.debug(IntelligentBookmarkUtil.class,
                "Calculated percentile threshold for " + programPath + ": " + threshold +
                " (percentile: " + percentile + "%)");
        }

        // Get reference count for this address
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refIter = refManager.getReferencesTo(address);

        int referenceCount = 0;
        boolean hasCallRef = false;
        boolean hasReadRef = false;
        boolean hasWriteRef = false;

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            referenceCount++;

            // Track reference types for intelligent bookmark type selection
            if (ref.getReferenceType().isCall()) {
                hasCallRef = true;
            } else if (ref.getReferenceType().isRead()) {
                hasReadRef = true;
            } else if (ref.getReferenceType().isWrite()) {
                hasWriteRef = true;
            }
        }

        // Only bookmark if threshold is exceeded
        if (referenceCount < threshold) {
            return false;
        }

        // Check if bookmark already exists
        BookmarkManager bookmarkMgr = program.getBookmarkManager();
        String bookmarkType = determineBookmarkType(program, address, hasCallRef, hasReadRef, hasWriteRef);
        String category = "Auto-Important";
        Bookmark existing = bookmarkMgr.getBookmark(address, bookmarkType, category);

        if (existing != null) {
            // Bookmark already exists, update comment with reference count
            try {
                int txId = program.startTransaction("Update auto-bookmark");
                try {
                    bookmarkMgr.removeBookmark(existing);
                    String comment = String.format("Auto-bookmarked: %d references (threshold: %d)",
                        referenceCount, threshold);
                    bookmarkMgr.setBookmark(address, bookmarkType, category, comment);
                    program.endTransaction(txId, true);
                    return true;
                } catch (Exception e) {
                    program.endTransaction(txId, false);
                    Msg.debug(IntelligentBookmarkUtil.class, "Failed to update bookmark: " + e.getMessage());
                    return false;
                }
            } catch (Exception e) {
                Msg.debug(IntelligentBookmarkUtil.class, "Failed to update bookmark: " + e.getMessage());
                return false;
            }
        }

        // Create new bookmark
        try {
            int txId = program.startTransaction("Auto-bookmark frequent address");
            try {
                String comment = String.format("Auto-bookmarked: %d references (threshold: %d)",
                    referenceCount, threshold);
                bookmarkMgr.setBookmark(address, bookmarkType, category, comment);
                program.endTransaction(txId, true);
                Msg.debug(IntelligentBookmarkUtil.class,
                    "Auto-bookmarked address " + AddressUtil.formatAddress(address) +
                    " with " + referenceCount + " references");
                return true;
            } catch (Exception e) {
                program.endTransaction(txId, false);
                Msg.debug(IntelligentBookmarkUtil.class, "Failed to create bookmark: " + e.getMessage());
                return false;
            }
        } catch (Exception e) {
            Msg.debug(IntelligentBookmarkUtil.class, "Failed to create bookmark: " + e.getMessage());
            return false;
        }
    }

    /**
     * Determine the appropriate bookmark type based on address context and reference types.
     *
     * @param program The program
     * @param address The address
     * @param hasCallRef Whether there are call references
     * @param hasReadRef Whether there are read references
     * @param hasWriteRef Whether there are write references
     * @return Bookmark type string
     */
    private static String determineBookmarkType(Program program, Address address,
            boolean hasCallRef, boolean hasReadRef, boolean hasWriteRef) {

        // Check if it's a function entry point
        if (program.getFunctionManager().getFunctionAt(address) != null) {
            return "Analysis"; // Function entry points get Analysis bookmarks
        }

        // Check if it's code
        if (program.getListing().getInstructionAt(address) != null) {
            if (hasCallRef) {
                return "Analysis"; // Called code locations
            }
            return "Note"; // Other code locations
        }

        // Check if it's data
        if (program.getListing().getDataAt(address) != null) {
            if (hasWriteRef) {
                return "Warning"; // Writable data (potentially important)
            }
            if (hasReadRef) {
                return "Note"; // Read-only data
            }
            return "Note"; // Other data
        }

        // Default to Note for unknown types
        return "Note";
    }

    /**
     * Calculate the percentile threshold for a program by collecting all reference counts
     * for functions, data, and other referenced addresses.
     *
     * @param program The program to analyze
     * @param percentile The percentile to calculate (95.0-99.0)
     * @return The reference count threshold at the specified percentile, or null if calculation fails
     */
    private static Integer calculatePercentileThreshold(Program program, double percentile) {
        try {
            List<Integer> referenceCounts = new ArrayList<>();
            ReferenceManager refManager = program.getReferenceManager();
            
            // Collect reference counts for all functions
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function func = functions.next();
                Address entryPoint = func.getEntryPoint();
                if (entryPoint != null) {
                    int refCount = countReferences(refManager, entryPoint);
                    if (refCount > 0) {
                        referenceCounts.add(refCount);
                    }
                }
            }
            
            // Collect reference counts for all data addresses
            Listing listing = program.getListing();
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                Address dataAddr = data.getAddress();
                if (dataAddr != null) {
                    int refCount = countReferences(refManager, dataAddr);
                    if (refCount > 0) {
                        referenceCounts.add(refCount);
                    }
                }
            }
            
            // If we have no reference counts, return null (don't bookmark anything)
            if (referenceCounts.isEmpty()) {
                Msg.debug(IntelligentBookmarkUtil.class,
                    "No reference counts found for program " + program.getDomainFile().getPathname());
                return null;
            }
            
            // Sort reference counts in descending order
            Collections.sort(referenceCounts, Collections.reverseOrder());
            
            // Calculate percentile index (top 2-5% means 95th-98th percentile)
            // For percentile P, we want the top (100-P)% of addresses
            // For 97th percentile: top 3% = 0.03 * size addresses
            // The threshold should be the value at index (topCount - 1) to include all top addresses
            // Example: 100 addresses, 97th percentile = top 3% = 3 addresses (indices 0,1,2)
            // Threshold should be at index 2 (the 3rd highest value)
            int size = referenceCounts.size();
            double topPercentage = (100.0 - percentile) / 100.0;
            int topCount = (int) Math.ceil(topPercentage * size);
            
            // The threshold is the value at index (topCount - 1) to include all top addresses
            // But we want at least 1 address bookmarked, so ensure topCount >= 1
            topCount = Math.max(1, Math.min(topCount, size));
            int percentileIndex = topCount - 1;
            
            // Ensure index is within bounds
            percentileIndex = Math.max(0, Math.min(percentileIndex, size - 1));
            
            int threshold = referenceCounts.get(percentileIndex);
            
            // Cache the reference counts for this program (useful for debugging)
            programReferenceCounts.put(program.getDomainFile().getPathname(), referenceCounts);
            
            Msg.debug(IntelligentBookmarkUtil.class,
                "Calculated percentile threshold: " + threshold + " (percentile: " + percentile +
                "%, index: " + percentileIndex + "/" + size + ", total addresses: " + size + ")");
            
            return threshold;
            
        } catch (Exception e) {
            Msg.debug(IntelligentBookmarkUtil.class,
                "Failed to calculate percentile threshold: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Count the number of references to a given address.
     *
     * @param refManager The reference manager
     * @param address The address to count references for
     * @return The number of references to the address
     */
    private static int countReferences(ReferenceManager refManager, Address address) {
        int count = 0;
        ReferenceIterator refIter = refManager.getReferencesTo(address);
        while (refIter.hasNext()) {
            refIter.next();
            count++;
        }
        return count;
    }

    /**
     * Get the default percentile for automatic bookmarking.
     *
     * @return Default percentile value
     */
    public static double getDefaultPercentile() {
        return DEFAULT_PERCENTILE;
    }

    /**
     * Clear cached thresholds and reference counts for a program (useful for cleanup).
     *
     * @param programPath The program path
     */
    public static void clearAccessCounts(String programPath) {
        programPercentileThresholds.remove(programPath);
        programReferenceCounts.remove(programPath);
    }
    
    /**
     * Force recalculation of percentile threshold for a program.
     * Useful when the program has been modified and reference counts may have changed.
     *
     * @param program The program to recalculate for
     * @param percentile The percentile to use (defaults to DEFAULT_PERCENTILE if <= 0)
     */
    public static void recalculateThreshold(Program program, double percentile) {
        if (program == null) {
            return;
        }
        String programPath = program.getDomainFile().getPathname();
        programPercentileThresholds.remove(programPath);
        programReferenceCounts.remove(programPath);
        
        if (percentile <= 0) {
            percentile = DEFAULT_PERCENTILE;
        }
        percentile = Math.max(MIN_PERCENTILE, Math.min(MAX_PERCENTILE, percentile));
        
        Integer threshold = calculatePercentileThreshold(program, percentile);
        if (threshold != null) {
            programPercentileThresholds.put(programPath, threshold);
        }
    }
}
