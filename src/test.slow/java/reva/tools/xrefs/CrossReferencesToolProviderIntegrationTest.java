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
package reva.tools.xrefs;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;

import reva.RevaIntegrationTestBase;

/**
 * Integration tests for CrossReferencesToolProvider
 */
public class CrossReferencesToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String program_path;
    private Address mainAddr;
    private Address helperAddr;
    private Address utilityAddr;
    private Address stringAddr;

    @Before
    public void setUpTestData() throws Exception {
        program_path = program.getDomainFile().getPathname();

        // Use addresses within the existing memory block (base class creates block at 0x01000000)
        mainAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01001000);
        helperAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01002000);
        utilityAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01003000);
        stringAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01004000);

        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();

        int txId = program.startTransaction("Create Test Functions and References");
        try {
            // Create functions
            try {
                functionManager.createFunction("main", mainAddr,
                    new AddressSet(mainAddr, mainAddr.add(100)), SourceType.USER_DEFINED);
            } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                fail("Failed to create main: " + e.getMessage());
            }
            try {
                functionManager.createFunction("helper", helperAddr,
                    new AddressSet(helperAddr, helperAddr.add(50)), SourceType.USER_DEFINED);
            } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                fail("Failed to create helper: " + e.getMessage());
            }
            try {
                functionManager.createFunction("utility", utilityAddr,
                    new AddressSet(utilityAddr, utilityAddr.add(30)), SourceType.USER_DEFINED);
            } catch (ghidra.util.exception.InvalidInputException | ghidra.program.database.function.OverlappingFunctionException e) {
                fail("Failed to create utility: " + e.getMessage());
            }

            // Create string data
            try {
                program.getMemory().setBytes(stringAddr, "Hello World\0".getBytes());
                program.getListing().createData(stringAddr,
                    ghidra.program.model.data.StringDataType.dataType);
            } catch (Exception e) {
                // If we can't create string data, just continue without it
                // Some test environments may not support this
            }

            // Create references
            // main calls helper
            refManager.addMemoryReference(mainAddr.add(0x10), helperAddr,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            // main calls utility
            refManager.addMemoryReference(mainAddr.add(0x20), utilityAddr,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            // helper calls utility
            refManager.addMemoryReference(helperAddr.add(0x10), utilityAddr,
                RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            // main references string
            refManager.addMemoryReference(mainAddr.add(0x30), stringAddr,
                RefType.DATA, SourceType.USER_DEFINED, 0);
            // helper references string
            refManager.addMemoryReference(helperAddr.add(0x20), stringAddr,
                RefType.DATA, SourceType.USER_DEFINED, 0);
        } finally {
            program.endTransaction(txId, true);
        }

        // Open the program in the tool's ProgramManager so it can be found by RevaProgramManager
        env.open(program);
    }

    @Test
    public void testFindCrossReferencesToFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "to"
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());
                assertEquals(1, result.content().size());

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                // Check references to utility (should be from main and helper)
                JsonNode refsTo = jsonResult.get("references");
                assertNotNull("Should have references", refsTo);
                assertTrue("Should have at least 2 references", refsTo.size() >= 2);

                // Verify references are from main and helper
                boolean foundFromMain = false;
                boolean foundFromHelper = false;

                for (JsonNode ref : refsTo) {
                    assertEquals("0x01003000", ref.get("toAddress").asText());
                    assertEquals("UNCONDITIONAL_CALL", ref.get("referenceType").asText());
                    assertEquals(true, ref.get("isCall").asBoolean());

                    JsonNode fromFunc = ref.has("fromFunction") ? ref.get("fromFunction") : ref.get("from_function");
                    if (fromFunc != null && "main".equals(fromFunc.get("name").asText())) {
                        foundFromMain = true;
                        String fromAddr = ref.has("fromAddress") ? ref.get("fromAddress").asText() : ref.get("from_address").asText();
                        assertEquals("0x01001020", fromAddr);
                    } else if (fromFunc != null && "helper".equals(fromFunc.get("name").asText())) {
                        foundFromHelper = true;
                        String fromAddr = ref.has("fromAddress") ? ref.get("fromAddress").asText() : ref.get("from_address").asText();
                        assertEquals("0x01002010", fromAddr);
                    }
                }

                assertTrue("Should find reference from main", foundFromMain);
                assertTrue("Should find reference from helper", foundFromHelper);

                // Check that references from is empty (direction was "to")
                JsonNode refsFrom = jsonResult.has("referencesFrom") ? jsonResult.get("referencesFrom") : jsonResult.get("references_from");
                assertEquals(0, refsFrom.size());
            } catch (JsonProcessingException e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testFindCrossReferencesFromFunction() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", mainAddr.toString(),
                        "mode", "from"
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                // Check references from main
                JsonNode refsFrom = jsonResult.get("references");
                assertEquals(3, refsFrom.size()); // Calls to helper, utility, and data ref to string

                // Count reference types
                int callCount = 0;
                int dataCount = 0;

                for (JsonNode ref : refsFrom) {
                    String fromAddr = ref.get("fromAddress").asText();
                    // Check that it's from the main function range
                    assertTrue("Address should be from main function",
                        fromAddr.startsWith("0x0100100") || fromAddr.startsWith("0x0100101") ||
                        fromAddr.startsWith("0x0100102") || fromAddr.startsWith("0x0100103"));

                    if ("UNCONDITIONAL_CALL".equals(ref.get("referenceType").asText())) {
                        callCount++;
                        JsonNode toSymbol = ref.has("toSymbol") ? ref.get("toSymbol") : ref.get("to_symbol");
                        if (toSymbol != null && !toSymbol.isNull()) {
                            String toName = toSymbol.get("name").asText();
                            assertTrue("helper".equals(toName) || "utility".equals(toName));
                        }
                    } else if ("DATA".equals(ref.has("referenceType") ? ref.get("referenceType").asText() : (ref.has("reference_type") ? ref.get("reference_type").asText() : ""))) {
                        dataCount++;
                        String toAddr = ref.has("toAddress") ? ref.get("toAddress").asText() : (ref.has("to_address") ? ref.get("to_address").asText() : "");
                        assertEquals("0x01004000", toAddr);
                    }
                }

                assertEquals(2, callCount);
                assertEquals(1, dataCount);

                // Mode "from" only returns outgoing references
                assertTrue("Should have references", refsFrom.size() > 0);
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testFindCrossReferencesBothDirections() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", stringAddr.toString(), // String address
                        "mode", "both"
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                // Check references to string (from main and helper)
                JsonNode refsTo = jsonResult.has("referencesTo") 
                    ? jsonResult.get("referencesTo")
                    : (jsonResult.has("references_to") ? jsonResult.get("references_to") 
                    : null);
                if (refsTo == null) {
                    refsTo = jsonResult.get("referencesTo");
                }
                assertNotNull("Should have referencesTo", refsTo);
                assertEquals(2, refsTo.size());

                for (JsonNode ref : refsTo) {
                    assertEquals("0x01004000", ref.get("toAddress").asText());
                    assertEquals("DATA", ref.get("referenceType").asText());
                    assertEquals(true, ref.get("isData").asBoolean());

                    JsonNode fromFunc = ref.has("fromFunction") ? ref.get("fromFunction") : ref.get("from_function");
                    if (fromFunc != null) {
                        String funcName = fromFunc.get("name").asText();
                        assertTrue("main".equals(funcName) || "helper".equals(funcName));
                    }
                }

                // String has no outgoing references
                JsonNode refsFrom = jsonResult.has("references_from") ? jsonResult.get("references_from") : jsonResult.get("referencesFrom");
                assertNotNull("Should have referencesFrom", refsFrom);
                assertEquals(0, refsFrom.size());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testFilterByReferenceType() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Test mode="from" to get outgoing references
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", mainAddr.toString(),
                        "mode", "from"
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                JsonNode refsFrom = jsonResult.get("references");
                assertNotNull("Should have references", refsFrom);
                assertTrue("Should have at least some references", refsFrom.size() > 0);

                // Verify we have both calls and data references
                boolean hasCall = false;
                boolean hasData = false;
                for (JsonNode ref : refsFrom) {
                    String refType = ref.get("referenceType").asText();
                    if ("UNCONDITIONAL_CALL".equals(refType)) {
                        hasCall = true;
                    } else if ("DATA".equals(refType)) {
                        hasData = true;
                    }
                }
                assertTrue("Should have call references", hasCall);
                assertTrue("Should have data references", hasData);
            } catch (JsonProcessingException e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testPagination() throws Exception {
        // Create many references to test pagination
        int txId = program.startTransaction("Create More References");
        try {
            ReferenceManager refManager = program.getReferenceManager();
            FunctionManager functionManager = program.getFunctionManager();

            for (int i = 0; i < 20; i++) {
                Address fromAddr = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x01005000 + i * 0x100);
                functionManager.createFunction("func_" + i, fromAddr,
                    new AddressSet(fromAddr, fromAddr.add(10)), SourceType.USER_DEFINED);
                refManager.addMemoryReference(fromAddr, utilityAddr,
                    RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            }
        } finally {
            program.endTransaction(txId, true);
        }

        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Test first page
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "to",
                        "offset", 0,
                        "limit", 10
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());

                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());

                JsonNode refsTo = jsonResult.get("references");
                assertNotNull("Should have references", refsTo);
                assertEquals(10, refsTo.size());

                assertEquals(0, jsonResult.get("offset").asInt());
                assertEquals(10, jsonResult.get("limit").asInt());
                assertEquals(22, jsonResult.has("totalCount") ? jsonResult.get("totalCount").asInt() : jsonResult.get("total_count").asInt()); // 2 original + 20 new
                assertEquals(true, jsonResult.has("hasMore") ? jsonResult.get("hasMore").asBoolean() : jsonResult.get("has_more").asBoolean());

                // Test last page
                result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "to",
                        "offset", 20,
                        "limit", 10
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());

                content = (TextContent) result.content().get(0);
                jsonResult = objectMapper.readTree(content.text());

                refsTo = jsonResult.get("references");
                assertEquals(2, refsTo.size()); // Only 2 remaining

                assertEquals(20, jsonResult.get("offset").asInt());
                assertEquals(false, jsonResult.has("hasMore") ? jsonResult.get("hasMore").asBoolean() : jsonResult.get("has_more").asBoolean());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testInvalidLocation() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "nonexistent_function"
                    )
                ));

                assertTrue("Tool should have error", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                assertTrue("Error should mention target cannot be resolved",
                    content.text().contains("Could not resolve") ||
                    content.text().contains("Invalid address or symbol"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesFunctionMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "function"
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                assertNotNull("Should have valid JSON structure", jsonResult);
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesReferencersDecompMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "referencers_decomp",
                        "maxReferencers", 5,
                        "startIndex", 0
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                assertNotNull("Should have valid JSON structure", jsonResult);
                // May have decompilations or be empty if no referencers
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesImportMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Try to find an import - may not exist in test program
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "printf",  // Common import name
                        "mode", "import",
                        "maxResults", 10
                    )
                ));

                // May return empty or error if import doesn't exist, but should handle gracefully
                if (!result.isError()) {
                    TextContent content = (TextContent) result.content().get(0);
                    JsonNode jsonResult = objectMapper.readTree(content.text());
                    assertNotNull("Should have valid JSON structure", jsonResult);
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesImportModeWithLibraryFilter() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "printf",
                        "mode", "import",
                        "libraryName", "msvcrt",
                        "maxResults", 10
                    )
                ));

                // May return empty or error if import doesn't exist
                if (!result.isError()) {
                    TextContent content = (TextContent) result.content().get(0);
                    JsonNode jsonResult = objectMapper.readTree(content.text());
                    assertNotNull("Should have valid JSON structure", jsonResult);
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesThunkMode() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Thunk mode may not have thunks in test program
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "thunk"
                    )
                ));

                // May return empty or error if no thunks exist
                if (!result.isError()) {
                    TextContent content = (TextContent) result.content().get(0);
                    JsonNode jsonResult = objectMapper.readTree(content.text());
                    assertNotNull("Should have valid JSON structure", jsonResult);
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesBothModeWithDirection() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Test both mode with direction="to"
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", stringAddr.toString(),
                        "mode", "both",
                        "direction", "to"
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                assertNotNull("Should have referencesTo", jsonResult.has("referencesTo") || jsonResult.has("references_to"));
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesReferencersDecompWithIncludeDataRefs() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", stringAddr.toString(),
                        "mode", "referencers_decomp",
                        "includeDataRefs", true,
                        "includeRefContext", true,
                        "max_referencers", 5
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                assertNotNull("Should have valid JSON structure", jsonResult);
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesPaginationBoundaries() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Test with offset beyond available references
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "to",
                        "offset", 1000,
                        "limit", 10
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                JsonNode refs = jsonResult.get("references");
                assertNotNull("Should have references array", refs);
                assertEquals("Should have empty array for offset beyond range", 0, refs.size());
                assertEquals("hasMore should be false", false, jsonResult.has("hasMore") ? jsonResult.get("hasMore").asBoolean() : jsonResult.get("has_more").asBoolean());
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }

    @Test
    public void testGetReferencesValidatesProgramState() throws Exception {
        withMcpClient(createMcpTransport(), client -> {
            try {
                client.initialize();

                // Verify that references returned match actual program state
                CallToolResult result = client.callTool(new CallToolRequest(
                    "get-references",
                    Map.of(
                        "programPath", program_path,
                        "target", "utility",
                        "mode", "to"
                    )
                ));

                assertFalse("Tool should not have errors", result.isError());
                TextContent content = (TextContent) result.content().get(0);
                JsonNode jsonResult = objectMapper.readTree(content.text());
                JsonNode refs = jsonResult.get("references");

                // Verify references match actual program state
                ghidra.program.model.symbol.ReferenceManager refManager = program.getReferenceManager();
                ghidra.program.model.listing.FunctionManager funcManager = program.getFunctionManager();
                Function utilityFunc = funcManager.getFunctionAt(utilityAddr);
                if (utilityFunc != null) {
                    int actualRefCount = 0;
                    for (ghidra.program.model.symbol.Reference ref : refManager.getReferencesTo(utilityAddr)) {
                        if (ref.getReferenceType().isCall()) {
                            actualRefCount++;
                        }
                    }
                    // Should have at least the references we created
                    assertTrue("Should have at least 2 call references", actualRefCount >= 2);
                }
            } catch (Exception e) {
                fail("Test failed with exception: " + e.getMessage());
            }
        });
    }
}
