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
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Collects log messages during tool execution to include in JSON responses.
 * This prevents log messages from interfering with JSON parsing while preserving
 * full visibility of all log output.
 */
public class ToolLogCollector {
    private final List<Map<String, Object>> logs = new ArrayList<>();
    private final ThreadLocal<Boolean> isActive = ThreadLocal.withInitial(() -> false);

    /**
     * Check if any logs have been collected
     * @return true if logs list is not empty
     */
    public boolean hasLogs() {
        return !logs.isEmpty();
    }

    /**
     * Start collecting logs for the current thread
     */
    public void start() {
        isActive.set(true);
        logs.clear();
    }

    /**
     * Stop collecting logs and return collected messages
     * @return List of log entries with level, message, and timestamp
     */
    public List<Map<String, Object>> stop() {
        isActive.set(false);
        List<Map<String, Object>> result = new ArrayList<>(logs);
        logs.clear();
        return result;
    }

    /**
     * Check if log collection is active
     */
    public boolean isActive() {
        return isActive.get();
    }

    /**
     * Add a log message
     * @param level Log level (INFO, WARN, DEBUG, ERROR)
     * @param message Log message
     */
    public void addLog(String level, String message) {
        if (isActive.get()) {
            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("level", level);
            logEntry.put("message", message);
            logEntry.put("timestamp", System.currentTimeMillis());
            logs.add(logEntry);
        }
    }

    /**
     * Add logs to a result map if any were collected
     * @param result The result map to add logs to
     * @param collector The log collector that was used
     */
    public static void addLogsToResult(Map<String, Object> result, ToolLogCollector collector) {
        if (collector != null && !collector.logs.isEmpty()) {
            result.put("logs", new ArrayList<>(collector.logs));
        }
    }
}

