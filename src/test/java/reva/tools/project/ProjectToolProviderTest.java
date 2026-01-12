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
import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;

/**
 * Unit tests for ProjectToolProvider.
 * Tests focus on validation and error handling since full functionality
 * requires a Ghidra environment.
 */
public class ProjectToolProviderTest {

    @Mock
    private McpSyncServer mockServer;

    private ProjectToolProvider toolProvider;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        toolProvider = new ProjectToolProvider(mockServer, false);
    }

    @Test
    public void testRegisterTools() throws McpError {
        // Test that tools can be registered without throwing exceptions
        try {
            toolProvider.registerTools();
        } catch (Exception e) {
            fail("Tool registration should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testInheritance() {
        // Test that ProjectToolProvider extends AbstractToolProvider
        assertTrue("ProjectToolProvider should extend AbstractToolProvider",
            reva.tools.AbstractToolProvider.class.isAssignableFrom(ProjectToolProvider.class));
    }

    @Test
    public void testToolProviderInterface() {
        // Test that ProjectToolProvider implements ToolProvider interface
        assertTrue("ProjectToolProvider should implement ToolProvider",
            reva.tools.ToolProvider.class.isAssignableFrom(ProjectToolProvider.class));
    }

    @Test
    public void testConstructor() {
        assertNotNull("ProjectToolProvider should be created", toolProvider);
    }
}
