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

/**
 * Shared tracker for tracking which functions have had their decompilations read.
 * This allows multiple tool providers (DecompilerToolProvider, CommentToolProvider, etc.)
 * to coordinate and know when a function's decompilation has been accessed.
 *
 * The tracker uses function keys in the format: "programPath:address" (e.g., "/program.exe:0x401000")
 * and stores timestamps to support expiry-based validation.
 */
public class DecompilationReadTracker {

    // Use 30 minutes to match DecompilerToolProvider's original expiry time
    // This is shorter than CommentToolProvider's 24 hours but ensures consistency
    // with the original read-before-modify enforcement pattern
    private static final long READ_TRACKING_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes

    // Shared tracker instance - thread-safe ConcurrentHashMap
    private static final Map<String, Long> tracker = new ConcurrentHashMap<>();

    /**
     * Record that a function's decompilation has been read.
     * @param functionKey The function key (format: "programPath:address")
     */
    public static void markAsRead(String functionKey) {
        tracker.put(functionKey, System.currentTimeMillis());
    }

    /**
     * Check if a function's decompilation has been read recently (within expiry window).
     * @param functionKey The function key (format: "programPath:address")
     * @return true if decompilation has been read within the expiry window, false otherwise
     */
    public static boolean hasReadDecompilation(String functionKey) {
        Long lastReadTime = tracker.get(functionKey);
        if (lastReadTime == null) {
            return false;
        }

        // Consider decompilation "read" if it was accessed within the expiry window
        long expiryThreshold = System.currentTimeMillis() - READ_TRACKING_EXPIRY_MS;
        return lastReadTime > expiryThreshold;
    }

    /**
     * Clear tracking entries for a specific program.
     * Called when a program is closed to clean up tracking data.
     * @param programPath The program path to clear entries for
     * @return The number of entries removed
     */
    public static int clearProgramEntries(String programPath) {
        int beforeSize = tracker.size();
        tracker.entrySet().removeIf(entry -> entry.getKey().startsWith(programPath + ":"));
        return beforeSize - tracker.size();
    }

    /**
     * Clear all tracking entries (useful for testing or reset).
     */
    public static void clearAll() {
        tracker.clear();
    }
}
