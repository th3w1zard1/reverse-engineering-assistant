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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;

/**
 * Utility for intelligent automatic bookmarking of frequently referenced addresses.
 *
 * This utility tracks address access frequency and automatically creates bookmarks
 * when addresses exceed a configurable threshold. This helps identify important
 * locations in the binary that are referenced multiple times.
 *
 * The bookmarking is intelligent in that it:
 * - Only bookmarks addresses that are actually referenced (not just accessed)
 * - Uses appropriate bookmark types based on context (function entry points, data, etc.)
 * - Avoids duplicate bookmarks
 * - Respects existing bookmarks
 */
public class IntelligentBookmarkUtil {

    /** Default threshold: bookmark addresses referenced 5+ times */
    private static final int DEFAULT_REFERENCE_THRESHOLD = 5;

    /** Minimum threshold to prevent bookmarking every address */
    private static final int MIN_THRESHOLD = 3;

    /** Maximum threshold to prevent excessive bookmarking */
    private static final int MAX_THRESHOLD = 100;

    /** Per-program address access counters */
    private static final Map<String, Map<Address, AtomicInteger>> programAccessCounts = new ConcurrentHashMap<>();

    /**
     * Check if an address should be automatically bookmarked based on reference count.
     * If the address exceeds the threshold, creates a bookmark automatically.
     *
     * @param program The program
     * @param address The address to check
     * @param threshold Minimum number of references required (defaults to DEFAULT_REFERENCE_THRESHOLD if <= 0)
     * @return true if a bookmark was created, false otherwise
     */
    public static boolean checkAndBookmarkIfFrequent(Program program, Address address, int threshold) {
        if (program == null || address == null) {
            return false;
        }

        // Use default threshold if invalid
        if (threshold <= 0) {
            threshold = DEFAULT_REFERENCE_THRESHOLD;
        }
        threshold = Math.max(MIN_THRESHOLD, Math.min(MAX_THRESHOLD, threshold));

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
     * Get the default reference threshold for automatic bookmarking.
     *
     * @return Default threshold value
     */
    public static int getDefaultThreshold() {
        return DEFAULT_REFERENCE_THRESHOLD;
    }

    /**
     * Clear access counts for a program (useful for cleanup).
     *
     * @param programPath The program path
     */
    public static void clearAccessCounts(String programPath) {
        programAccessCounts.remove(programPath);
    }
}
