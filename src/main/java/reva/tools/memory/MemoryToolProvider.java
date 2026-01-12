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
package reva.tools.memory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.MemoryUtil;
import reva.util.SchemaUtil;

/**
 * Tool provider for memory-related operations.
 * Provides tools to list memory blocks and read memory content.
 */
public class MemoryToolProvider extends AbstractToolProvider {

    /**
     * Constructor
     * @param server The MCP server
     */
    public MemoryToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerInspectMemoryTool();
    }

    private void registerInspectMemoryTool() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Path to the program in the Ghidra Project"));
        properties.put("mode", Map.of(
            "type", "string",
            "description", "Inspection mode: 'blocks', 'read', 'data_at', 'data_items', or 'segments'",
            "enum", List.of("blocks", "read", "data_at", "data_items", "segments")
        ));
        properties.put("address", SchemaUtil.stringProperty("Address to read from when mode='read' or address to query when mode='data_at' (required for read/data_at modes)"));
        properties.put("length", SchemaUtil.integerPropertyWithDefault("Number of bytes to read when mode='read'", 16));
        properties.put("offset", SchemaUtil.integerPropertyWithDefault("Pagination offset when mode='data_items' or 'segments'", 0));
        properties.put("limit", SchemaUtil.integerPropertyWithDefault("Maximum number of items to return when mode='data_items' or 'segments'", 100));

        List<String> required = List.of("programPath", "mode");

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("inspect_memory")
            .title("Inspect Memory")
            .description("Inspect memory blocks, read memory, get data information, list data items, or list memory segments.")
            .inputSchema(createSchema(properties, required))
            .build();

        registerTool(tool, (exchange, request) -> {
            try {
                Program program = getProgramFromArgs(request);
                String mode = getString(request, "mode");

                switch (mode) {
                    case "blocks":
                        return handleBlocksMode(program);
                    case "read":
                        return handleReadMode(program, request);
                    case "data_at":
                        return handleDataAtMode(program, request);
                    case "data_items":
                        return handleDataItemsMode(program, request);
                    case "segments":
                        return handleSegmentsMode(program, request);
                    default:
                        return createErrorResult("Invalid mode: " + mode + ". Valid modes are: blocks, read, data_at, data_items, segments");
                }
            } catch (IllegalArgumentException e) {
                return createErrorResult(e.getMessage());
            } catch (Exception e) {
                logError("Error in inspect_memory", e);
                return createErrorResult("Tool execution failed: " + e.getMessage());
            }
        });
    }

    private McpSchema.CallToolResult handleBlocksMode(Program program) {
        Memory memory = program.getMemory();
        List<Map<String, Object>> blockData = new ArrayList<>();

        for (MemoryBlock block : memory.getBlocks()) {
            Map<String, Object> blockInfo = new HashMap<>();
            blockInfo.put("name", block.getName());
            blockInfo.put("start", AddressUtil.formatAddress(block.getStart()));
            blockInfo.put("end", AddressUtil.formatAddress(block.getEnd()));
            blockInfo.put("size", block.getSize());
            blockInfo.put("readable", block.isRead());
            blockInfo.put("writable", block.isWrite());
            blockInfo.put("executable", block.isExecute());
            blockInfo.put("initialized", block.isInitialized());
            blockInfo.put("volatile", block.isVolatile());
            blockInfo.put("mapped", block.isMapped());
            blockInfo.put("overlay", block.isOverlay());
            blockData.add(blockInfo);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("blocks", blockData);
        result.put("count", blockData.size());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleReadMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='read'");
        }
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        int length = getOptionalInt(request, "length", 16);
        if (length <= 0) {
            return createErrorResult("Invalid length: " + length);
        }
        if (length > 10000) {
            length = 10000; // Limit to prevent huge responses
        }

        byte[] bytes = MemoryUtil.readMemoryBytes(program, address, length);
        if (bytes == null) {
            return createErrorResult("Memory access error at address: " + AddressUtil.formatAddress(address));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("address", AddressUtil.formatAddress(address));
        result.put("length", bytes.length);
        String hexString = MemoryUtil.formatHexString(bytes);
        result.put("hex", hexString);
        result.put("hexDump", hexString);
        result.put("data", hexString);
        result.put("ascii", MemoryUtil.formatAsciiString(bytes));
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleDataAtMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        String addressStr = getOptionalString(request, "address", null);
        if (addressStr == null) {
            return createErrorResult("address is required for mode='data_at'");
        }
        Address address = AddressUtil.resolveAddressOrSymbol(program, addressStr);
        if (address == null) {
            return createErrorResult("Could not resolve address or symbol: " + addressStr);
        }

        Data data = AddressUtil.getContainingData(program, address);
        if (data == null) {
            return createErrorResult("No data found at address: " + AddressUtil.formatAddress(address));
        }

        Map<String, Object> resultData = new HashMap<>();
        resultData.put("address", AddressUtil.formatAddress(data.getAddress()));
        resultData.put("dataType", data.getDataType().getName());
        resultData.put("length", data.getLength());

        SymbolTable symbolTable = program.getSymbolTable();
        Symbol primarySymbol = symbolTable.getPrimarySymbol(data.getAddress());
        if (primarySymbol != null) {
            resultData.put("symbolName", primarySymbol.getName());
            resultData.put("symbolNamespace", primarySymbol.getParentNamespace().getName());
        }

        StringBuilder hexString = new StringBuilder();
        try {
            byte[] bytes = data.getBytes();
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b & 0xff));
            }
            resultData.put("hexBytes", hexString.toString());
        } catch (MemoryAccessException e) {
            resultData.put("hexBytesError", "Memory access error: " + e.getMessage());
        }

        String representation = data.getDefaultValueRepresentation();
        resultData.put("representation", representation);

        Object value = data.getValue();
        if (value != null) {
            resultData.put("valueType", value.getClass().getSimpleName());
            resultData.put("value", value.toString());
        } else {
            resultData.put("value", null);
        }

        return createJsonResult(resultData);
    }

    private McpSchema.CallToolResult handleDataItemsMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);
        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        Listing listing = program.getListing();
        List<Map<String, Object>> dataItems = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && dataItems.size() < limit) {
            Data data = dataIter.next();
            count++;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            Map<String, Object> item = new HashMap<>();
            item.put("address", AddressUtil.formatAddress(data.getAddress()));
            item.put("dataType", data.getDataType().getName());
            item.put("length", data.getLength());
            item.put("representation", data.getDefaultValueRepresentation());

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol primarySymbol = symbolTable.getPrimarySymbol(data.getAddress());
            if (primarySymbol != null) {
                item.put("label", primarySymbol.getName());
            }

            Object value = data.getValue();
            if (value != null) {
                item.put("value", value.toString());
            }

            dataItems.add(item);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("dataItems", dataItems);
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("returned", dataItems.size());
        result.put("hasMore", dataIter.hasNext());
        return createJsonResult(result);
    }

    private McpSchema.CallToolResult handleSegmentsMode(Program program, io.modelcontextprotocol.spec.McpSchema.CallToolRequest request) {
        int offset = getOptionalInt(request, "offset", 0);
        int limit = getOptionalInt(request, "limit", 100);
        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;

        Memory memory = program.getMemory();
        List<MemoryBlock> allBlocks = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            allBlocks.add(block);
        }

        List<Map<String, Object>> segments = new ArrayList<>();
        int endIndex = Math.min(offset + limit, allBlocks.size());
        for (int i = offset; i < endIndex; i++) {
            MemoryBlock block = allBlocks.get(i);
            Map<String, Object> segmentInfo = new HashMap<>();
            segmentInfo.put("name", block.getName());
            segmentInfo.put("start", AddressUtil.formatAddress(block.getStart()));
            segmentInfo.put("end", AddressUtil.formatAddress(block.getEnd()));
            segmentInfo.put("size", block.getSize());
            segmentInfo.put("readable", block.isRead());
            segmentInfo.put("writable", block.isWrite());
            segmentInfo.put("executable", block.isExecute());
            segments.add(segmentInfo);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("segments", segments);
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("totalCount", allBlocks.size());
        result.put("hasMore", endIndex < allBlocks.size());
        return createJsonResult(result);
    }


}
