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

/**
 * Utility class for reading default parameter values from environment variables.
 * Environment variables follow the pattern: REVA_<PARAMETER_NAME>
 * where PARAMETER_NAME is the parameter name in UPPER_SNAKE_CASE.
 *
 * Examples:
 * - auto_label -> REVA_AUTO_LABEL
 * - auto_tag -> REVA_AUTO_TAG
 * - max_results -> REVA_MAX_RESULTS
 * - analyze_after_import -> REVA_ANALYZE_AFTER_IMPORT
 */
public class EnvConfigUtil {

    /**
     * Get a boolean default value from environment variable.
     * Checks REVA_<PARAMETER_NAME> environment variable.
     *
     * @param parameterName The parameter name (snake_case or camelCase)
     * @param defaultValue The default value if environment variable is not set
     * @return The value from environment variable, or defaultValue if not set
     */
    public static boolean getBooleanDefault(String parameterName, boolean defaultValue) {
        String envVarName = toEnvVarName(parameterName);
        String envValue = System.getenv(envVarName);
        if (envValue == null) {
            return defaultValue;
        }

        String normalized = envValue.trim().toLowerCase();
        return "true".equals(normalized) || "1".equals(normalized) || "yes".equals(normalized);
    }

    /**
     * Get a string default value from environment variable.
     * Checks REVA_<PARAMETER_NAME> environment variable.
     *
     * @param parameterName The parameter name (snake_case or camelCase)
     * @param defaultValue The default value if environment variable is not set
     * @return The value from environment variable, or defaultValue if not set
     */
    public static String getStringDefault(String parameterName, String defaultValue) {
        String envVarName = toEnvVarName(parameterName);
        String envValue = System.getenv(envVarName);
        if (envValue == null || envValue.trim().isEmpty()) {
            return defaultValue;
        }
        return envValue.trim();
    }

    /**
     * Get an integer default value from environment variable.
     * Checks REVA_<PARAMETER_NAME> environment variable.
     *
     * @param parameterName The parameter name (snake_case or camelCase)
     * @param defaultValue The default value if environment variable is not set
     * @return The value from environment variable, or defaultValue if not set or invalid
     */
    public static int getIntDefault(String parameterName, int defaultValue) {
        String envVarName = toEnvVarName(parameterName);
        String envValue = System.getenv(envVarName);
        if (envValue == null || envValue.trim().isEmpty()) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(envValue.trim());
        } catch (NumberFormatException e) {
            // Invalid format, return default
            return defaultValue;
        }
    }

    /**
     * Convert a parameter name to environment variable name.
     * Converts snake_case or camelCase to REVA_UPPER_SNAKE_CASE.
     *
     * Examples:
     * - auto_label -> REVA_AUTO_LABEL
 * - auto_tag -> REVA_AUTO_TAG
     * - autoLabel -> REVA_AUTO_LABEL
     * - autoTag -> REVA_AUTO_TAG
     * - max_results -> REVA_MAX_RESULTS
     * - analyzeAfterImport -> REVA_ANALYZE_AFTER_IMPORT
     *
     * @param parameterName The parameter name
     * @return The environment variable name
     */
    private static String toEnvVarName(String parameterName) {
        if (parameterName == null || parameterName.isEmpty()) {
            return "REVA_";
        }

        // Convert camelCase to snake_case first if needed
        if (parameterName.matches(".*[a-z][A-Z].*")) {
            // Has camelCase pattern, convert to snake_case
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parameterName.length(); i++) {
                char c = parameterName.charAt(i);
                if (Character.isUpperCase(c) && i > 0) {
                    sb.append('_');
                }
                sb.append(Character.toUpperCase(c));
            }
            return "REVA_" + sb.toString();
        } else {
            // Already snake_case, just uppercase
            return "REVA_" + parameterName.toUpperCase();
        }
    }
}
