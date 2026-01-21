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

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.spec.McpSchema;
import reva.RevaIntegrationTestBase;
import reva.plugin.RevaProgramManager;

/**
 * Integration tests for version control operations in ProjectToolProvider.
 * Tests fix for issue #154 (save before checkin) and save fallback for unversioned files.
 */
public class ProjectToolProviderVersionControlIntegrationTest extends RevaIntegrationTestBase {

    @Before
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    /**
     * Test checkin-program works correctly.
     * This test verifies the fix for issue #154 - the tool should handle saves properly.
     */
    @Test
    public void testCheckinProgram() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program
                testProgram = createDefaultProgram("test-checkin", "x86:LE:64:default", this);
                String program_path = testProgram.getDomainFile().getPathname();

                // Register the program so it can be found by tools
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Make changes to the program (add a label)
                int transactionID = testProgram.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = testProgram.getSymbolTable();
                    symbolTable.createLabel(testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000),
                        "test_label", SourceType.USER_DEFINED);
                    testProgram.endTransaction(transactionID, true);
                } catch (AddressOutOfBoundsException | InvalidInputException e) {
                    testProgram.endTransaction(transactionID, false);
                    throw e;
                }

                // Try to checkin - this should save first, then add to version control or save
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", program_path,
                        "message", "Test commit"
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                if (result.isError()) {
                    // Print error for debugging
                    String errorMsg = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                    System.err.println("Tool error: " + errorMsg);
                }
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Checkin should be successful", Boolean.TRUE.equals(response.get("success")));

                // Should either be added_to_version_control (new file) or saved (if not versioned)
                String action = (String) response.get("action");
                assertTrue("Action should be added_to_version_control or saved",
                    "added_to_version_control".equals(action) || "saved".equals(action));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                // Clean up the test program
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * Test checkin-program returns appropriate action based on version control support.
     * This test verifies that the tool handles both versioned and unversioned files correctly.
     */
    @Test
    public void testCheckinHandlesVersionControlStatus() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program
                testProgram = createDefaultProgram("test-unversioned", "x86:LE:64:default", this);
                String program_path = testProgram.getDomainFile().getPathname();
                DomainFile domainFile = testProgram.getDomainFile();

                // Register the program so it can be found by tools
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Make changes to the program
                int transactionID = testProgram.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = testProgram.getSymbolTable();
                    symbolTable.createLabel(testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000),
                        "test_label_unversioned", SourceType.USER_DEFINED);
                    testProgram.endTransaction(transactionID, true);
                } catch (AddressOutOfBoundsException | InvalidInputException e) {
                    testProgram.endTransaction(transactionID, false);
                    throw e;
                }

                // Check if file can be added to version control
                boolean canAddToVCS = domainFile.canAddToRepository();

                // Try to checkin - should work regardless of version control support
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", program_path,
                        "message", "Test commit"
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                if (result.isError()) {
                    // Print error for debugging
                    String errorMsg = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                    System.err.println("Tool error: " + errorMsg);
                }
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Operation should be successful", Boolean.TRUE.equals(response.get("success")));

                // Action should depend on version control support
                String action = (String) response.get("action");
                assertNotNull("Action should be present", action);

                if (canAddToVCS) {
                    assertEquals("Action should be added_to_version_control when supported", "added_to_version_control", action);
                } else {
                    assertEquals("Action should be saved when version control not supported", "saved", action);
                    assertFalse("Response should indicate file is not versioned", Boolean.TRUE.equals(response.get("is_versioned")));
                }

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                // Clean up the test program
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * Test that checkin-program accepts commit message parameter.
     */
    @Test
    public void testCheckinWithCommitMessage() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program
                testProgram = createDefaultProgram("test-message", "x86:LE:64:default", this);
                String program_path = testProgram.getDomainFile().getPathname();

                // Register the program so it can be found by tools
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Make changes to the program
                int transactionID = testProgram.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = testProgram.getSymbolTable();
                    symbolTable.createLabel(testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x3000),
                        "test_label_message", SourceType.USER_DEFINED);
                    testProgram.endTransaction(transactionID, true);
                } catch (AddressOutOfBoundsException | InvalidInputException e) {
                    testProgram.endTransaction(transactionID, false);
                    throw e;
                }

                String commitMessage = "Test commit message for version control";

                // Try to checkin with specific message
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "checkin-program",
                    Map.of(
                        "programPath", program_path,
                        "message", commitMessage
                    )
                ));

                // Verify the response
                assertNotNull("Result should not be null", result);
                if (result.isError()) {
                    // Print error for debugging
                    String errorMsg = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                    System.err.println("Tool error: " + errorMsg);
                }
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Operation should be successful", Boolean.TRUE.equals(response.get("success")));
                assertEquals("Response should include the commit message", commitMessage, response.get("message"));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                // Clean up the test program
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * Test checkout operation via manage-files tool.
     */
    @Test
    public void testCheckoutOperation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program and add it to version control
                testProgram = createDefaultProgram("test-checkout", "x86:LE:64:default", this);
                String program_path = testProgram.getDomainFile().getPathname();
                DomainFile domainFile = testProgram.getDomainFile();

                // Register the program
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Check if version control is available
                if (!domainFile.canAddToRepository()) {
                    // Skip test if version control not available
                    System.out.println("Version control not available, skipping checkout test");
                    return null;
                }

                // Add to version control and checkin first
                testProgram.save("Initial save", null);
                domainFile.addToVersionControl("Initial checkin", false, null);

                // Release program from cache
                testProgram.release(this);
                RevaProgramManager.unregisterProgram(testProgram);

                // Now test checkout
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "manage-files",
                    Map.of(
                        "operation", "checkout",
                        "programPath", program_path,
                        "exclusive", false
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Checkout should be successful", Boolean.TRUE.equals(response.get("success")));
                assertEquals("Action should be checked_out", "checked_out", response.get("action"));
                assertTrue("Program should be checked out", Boolean.TRUE.equals(response.get("isCheckedOut")));

                // Verify the domain file is actually checked out
                assertTrue("Domain file should be checked out", domainFile.isCheckedOut());

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * Test uncheckout operation via manage-files tool.
     */
    @Test
    public void testUncheckoutOperation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program and add it to version control
                testProgram = createDefaultProgram("test-uncheckout", "x86:LE:64:default", this);
                String program_path = testProgram.getDomainFile().getPathname();
                DomainFile domainFile = testProgram.getDomainFile();

                // Register the program
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Check if version control is available
                if (!domainFile.canAddToRepository()) {
                    System.out.println("Version control not available, skipping uncheckout test");
                    return null;
                }

                // Add to version control and checkin first
                testProgram.save("Initial save", null);
                domainFile.addToVersionControl("Initial checkin", true, null); // Keep checked out

                // Make some changes
                int transactionID = testProgram.startTransaction("Add test label");
                try {
                    SymbolTable symbolTable = testProgram.getSymbolTable();
                    symbolTable.createLabel(testProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x4000),
                        "test_label_uncheckout", SourceType.USER_DEFINED);
                    testProgram.endTransaction(transactionID, true);
                } catch (AddressOutOfBoundsException | InvalidInputException e) {
                    testProgram.endTransaction(transactionID, false);
                    throw e;
                }

                // Release program from cache
                RevaProgramManager.releaseProgramFromCache(testProgram);
                RevaProgramManager.unregisterProgram(testProgram);

                // Now test uncheckout
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "manage-files",
                    Map.of(
                        "operation", "uncheckout",
                        "programPath", program_path
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Uncheckout should be successful", Boolean.TRUE.equals(response.get("success")));
                assertEquals("Action should be unchecked_out", "unchecked_out", response.get("action"));
                assertFalse("Program should not be checked out", Boolean.TRUE.equals(response.get("isCheckedOut")));

                // Verify the domain file is actually unchecked out
                assertFalse("Domain file should not be checked out", domainFile.isCheckedOut());

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }

    /**
     * Test unhijack operation via manage-files tool.
     */
    @Test
    public void testUnhijackOperation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            Program testProgram = null;
            try {
                client.initialize();

                // Create a test program and add it to version control
                testProgram = createDefaultProgram("test-unhijack", "x86:LE:64:default", this);
                String program_path = testProgram.getDomainFile().getPathname();
                DomainFile domainFile = testProgram.getDomainFile();

                // Register the program
                RevaProgramManager.registerProgram(testProgram);
                if (serverManager != null) {
                    serverManager.programOpened(testProgram, tool);
                }

                // Check if version control is available
                if (!domainFile.canAddToRepository()) {
                    System.out.println("Version control not available, skipping unhijack test");
                    return null;
                }

                // Add to version control and checkin first
                testProgram.save("Initial save", null);
                domainFile.addToVersionControl("Initial checkin", false, null); // Check in

                // Release program from cache
                testProgram.release(this);
                RevaProgramManager.unregisterProgram(testProgram);

                // Test unhijack on non-hijacked file (should return appropriate response)
                McpSchema.CallToolResult result = client.callTool(new McpSchema.CallToolRequest(
                    "manage-files",
                    Map.of(
                        "operation", "unhijack",
                        "programPath", program_path
                    )
                ));

                assertNotNull("Result should not be null", result);
                assertFalse("Tool should not have error", result.isError());

                String responseJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(0)).text();
                Map<String, Object> response = objectMapper.readValue(responseJson, new TypeReference<Map<String, Object>>() {});

                assertTrue("Unhijack should be successful", Boolean.TRUE.equals(response.get("success")));
                // Should either be "not_hijacked" or "unhijacked" depending on state
                String action = (String) response.get("action");
                assertTrue("Action should be not_hijacked or unhijacked",
                    "not_hijacked".equals(action) || "unhijacked".equals(action));

                return null;
            } catch (Exception e) {
                throw new RuntimeException("Test failed", e);
            } finally {
                if (testProgram != null) {
                    RevaProgramManager.unregisterProgram(testProgram);
                    if (serverManager != null) {
                        serverManager.programClosed(testProgram, tool);
                    }
                    testProgram.release(this);
                }
            }
        });
    }
}
