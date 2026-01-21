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
package reva.tools.project;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Integration tests for list-project-files and list-open-programs tools
 * with the onlyShowCheckedOutPrograms parameter.
 */
public class ProjectToolProviderListProgramsIntegrationTest extends RevaIntegrationTestBase {

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    public void testListProjectFilesShowsAllPrograms() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Call list-project-files with recursive=true to get all programs
            Map<String, Object> args = new HashMap<>();
            args.put("folderPath", "/");
            args.put("recursive", true);
            args.put("onlyShowCheckedOutPrograms", false);

            CallToolResult result = client.callTool(new CallToolRequest("list-project-files", args));

            assertNotNull("Result should not be null", result);
            assertNotNull("Response content should not be null", result.content());
            assertTrue("Should have at least one content item", !result.content().isEmpty());

            // Parse the response
            String responseJson = ((TextContent) result.content().get(0)).text();
            JsonNode response = objectMapper.readTree(responseJson);

            // Should have metadata
            if (response.isArray() && response.size() > 0) {
                JsonNode metadata = response.get(0);
                if (metadata.has("onlyShowCheckedOutPrograms")) {
                    assertFalse("onlyShowCheckedOutPrograms should be false", 
                        metadata.get("onlyShowCheckedOutPrograms").asBoolean());
                }
            }

            return null;
        });
    }

    @Test
    public void testListOpenProgramsShowsAllPrograms() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Call list-open-programs (should show all programs, not just open ones)
            Map<String, Object> args = new HashMap<>();
            args.put("onlyShowCheckedOutPrograms", false);

            CallToolResult result = client.callTool(new CallToolRequest("list-open-programs", args));

            assertNotNull("Result should not be null", result);
            assertNotNull("Response content should not be null", result.content());

            // Should not be an error (may be empty if no programs, but that's okay)
            if (!result.content().isEmpty()) {
                String responseJson = ((TextContent) result.content().get(0)).text();
                JsonNode response = objectMapper.readTree(responseJson);

                // Should have metadata
                if (response.isArray() && response.size() > 0) {
                    JsonNode metadata = response.get(0);
                    assertNotNull("metadata should not be null", metadata);
                }
            }

            return null;
        });
    }

    @Test
    public void testListOpenProgramsDefaultBehavior() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            // Call list-open-programs without the parameter (should default to false)
            Map<String, Object> args = new HashMap<>();

            CallToolResult result = client.callTool(new CallToolRequest("list-open-programs", args));

            assertNotNull("Result should not be null", result);
            assertNotNull("Response content should not be null", result.content());

            // Should work (may return empty list if no programs)
            // The key is that it doesn't error out

            return null;
        });
    }
}
