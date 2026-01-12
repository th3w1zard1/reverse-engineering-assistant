# CLAUDE.md - Symbols Tools Package

This file provides guidance to Claude Code when working with the symbols tools package in ReVa.

## Package Overview

The symbols tools package (`reva.tools.symbols`) provides MCP tools for interacting with Ghidra's symbol table operations. This includes retrieving symbol information with pagination, counting symbols, listing imports/exports, creating labels, renaming data, and understanding symbol metadata across programs.

## Key Tools

### manage_symbols

**Consolidated tool that replaces:** `list_classes`, `list_namespaces`, `list_imports`, `list_exports`, `create_label`, `get_symbols`, `get_symbols_count`, `rename_data`

List classes, namespaces, imports, exports, create labels, get symbols, count symbols, or rename data labels.

**Parameters:**
- `programPath` (required) - Path to the program in the Ghidra Project
- `mode` (required) - Operation mode: 'classes', 'namespaces', 'imports', 'exports', 'create_label', 'symbols', 'count', 'rename_data'
- `address` (required for mode='create_label'/'rename_data') - Address where to create the label or address of data to rename
- `label_name` (required for mode='create_label') - Name for the label
- `new_name` (required for mode='rename_data') - New name for the data label
- `library_filter` (optional for mode='imports') - Optional library name to filter by (case-insensitive)
- `max_results` (optional for mode='imports'/'exports', default: 500) - Maximum number of imports/exports to return
- `start_index` (optional, default: 0) - Starting index for pagination (0-based)
- `offset` (optional, default: 0) - Alternative pagination offset parameter (backward compatibility)
- `limit` (optional, default: 100) - Alternative pagination limit parameter (backward compatibility)
- `group_by_library` (optional for mode='imports', default: true) - Whether to group imports by library name
- `include_external` (optional for mode='symbols'/'count', default: false) - Whether to include external symbols
- `max_count` (optional for mode='symbols', default: 200) - Maximum number of symbols to return
- `filter_default_names` (optional for mode='symbols'/'count', default: true) - Whether to filter out default Ghidra generated names

**Modes:**

1. **mode='classes'** - List all namespace/class names with pagination
2. **mode='namespaces'** - List all non-global namespaces with pagination
3. **mode='imports'** - List all imported functions from external libraries with filtering and grouping
4. **mode='exports'** - List all exported symbols from the binary
5. **mode='create_label'** - Create a label at a specific address
6. **mode='symbols'** - Retrieve symbols from a program with pagination support
7. **mode='count'** - Get total count of symbols (use before pagination)
8. **mode='rename_data'** - Rename a data label at a specific address

## Symbol Table Operations

### Basic Symbol Access Patterns
```java
// Get symbol table from program
SymbolTable symbolTable = program.getSymbolTable();

// Iterate over all symbols
SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

// Count symbols with filtering
AtomicInteger count = new AtomicInteger(0);
symbolIterator.forEach(symbol -> {
    if (!includeExternal && symbol.isExternal()) {
        return; // Skip external symbols
    }
    
    if (!filterDefaultNames || !SymbolUtil.isDefaultSymbolName(symbol.getName())) {
        count.incrementAndGet();
    }
});
```

### Symbol Information Extraction
```java
// Create symbol metadata map
Map<String, Object> symbolInfo = new HashMap<>();
symbolInfo.put("name", symbol.getName());
symbolInfo.put("address", AddressUtil.formatAddress(symbol.getAddress()));
symbolInfo.put("namespace", symbol.getParentNamespace().getName());
symbolInfo.put("id", symbol.getID());
symbolInfo.put("symbolType", symbol.getSymbolType().toString());
symbolInfo.put("isPrimary", symbol.isPrimary());
symbolInfo.put("isExternal", symbol.isExternal());

// Function-specific metadata
if (symbol.getSymbolType() == SymbolType.FUNCTION) {
    symbolInfo.put("isFunction", true);
}
```

## Symbol Creation and Modification Patterns

### Label Creation with Transactions
```java
// Start transaction for symbol modifications
int transactionID = program.startTransaction("Create Label");
boolean success = false;

try {
    SymbolTable symbolTable = program.getSymbolTable();
    
    // Create label at address
    Symbol symbol = symbolTable.createLabel(address, labelName,
        program.getGlobalNamespace(), SourceType.USER_DEFINED);
    
    if (symbol == null) {
        throw new Exception("Failed to create label at address: " + address);
    }
    
    // Set as primary if requested
    if (setAsPrimary && !symbol.isPrimary()) {
        symbol.setPrimary();
    }
    
    success = true;
} finally {
    program.endTransaction(transactionID, success);
}
```

### Symbol Lookup and Validation
```java
// Get primary symbol at address
Symbol primarySymbol = symbolTable.getPrimarySymbol(address);

// Check for existing symbols before creation
Symbol[] existingSymbols = symbolTable.getSymbols(address);
if (existingSymbols.length > 0) {
    // Handle conflicts or use existing symbol
}
```

## Symbol Type Handling

### Common Symbol Types
- `SymbolType.FUNCTION` - Function entry points
- `SymbolType.LABEL` - User-defined labels
- `SymbolType.GLOBAL_VAR` - Global variables
- `SymbolType.LOCAL_VAR` - Local variables
- `SymbolType.PARAMETER` - Function parameters
- `SymbolType.NAMESPACE` - Namespace containers
- `SymbolType.CLASS` - Class definitions

### Symbol Type Checks
```java
// Check if symbol is a function
if (symbol.getSymbolType() == SymbolType.FUNCTION) {
    // Handle function-specific logic
    symbolInfo.put("isFunction", true);
} else {
    symbolInfo.put("isFunction", false);
}

// Check for external symbols
if (symbol.isExternal()) {
    // Handle external symbol differently
}
```

## Name Validation and Conflict Resolution

### Default Name Filtering
```java
// Use SymbolUtil to check for default Ghidra names
if (SymbolUtil.isDefaultSymbolName(symbol.getName())) {
    // Skip default names like FUN_, DAT_, LAB_, etc.
    return;
}
```

### Default Name Pattern Recognition
The `SymbolUtil.isDefaultSymbolName()` method recognizes these patterns:
- `FUN_[hex]` - Function names
- `LAB_[hex]` - Label names  
- `SUB_[hex]` - Subroutine names
- `DAT_[hex]` - Data names
- `EXT_[hex]` - External names
- `PTR_[hex]` - Pointer names
- `ARRAY_[hex]` - Array names

### Name Validation
```java
// Validate label name before creation
if (labelName.trim().isEmpty()) {
    return createErrorResult("Label name cannot be empty");
}

// Check for naming conflicts
Symbol existingSymbol = symbolTable.getGlobalSymbol(labelName, address);
if (existingSymbol != null) {
    // Handle naming conflict
}
```

## SourceType Management for Symbol Provenance

### SourceType Usage
```java
// Create user-defined symbols
Symbol symbol = symbolTable.createLabel(address, labelName,
    program.getGlobalNamespace(), SourceType.USER_DEFINED);

// Other common source types:
// SourceType.ANALYSIS - Created by analysis
// SourceType.IMPORTED - From imports
// SourceType.DEFAULT - Default/generated names
```

### Symbol Priority
- `USER_DEFINED` - Highest priority, user-created symbols
- `IMPORTED` - From import processing
- `ANALYSIS` - From automatic analysis
- `DEFAULT` - Lowest priority, auto-generated

## Namespace Operations

### Working with Namespaces
```java
// Get symbol's namespace
Namespace parentNamespace = symbol.getParentNamespace();
String namespaceName = parentNamespace.getName();

// Global namespace
Namespace globalNamespace = program.getGlobalNamespace();

// Create symbols in global namespace
Symbol symbol = symbolTable.createLabel(address, labelName, 
    globalNamespace, SourceType.USER_DEFINED);
```

### Namespace Hierarchy
```java
// Get full namespace path
StringBuilder namespacePath = new StringBuilder();
Namespace current = symbol.getParentNamespace();
while (current != null && !current.isGlobal()) {
    namespacePath.insert(0, current.getName() + "::");
    current = current.getParentNamespace();
}
```

## Response Formats for Symbol Data

### Symbol Count Response
```json
{
  "count": 1250,
  "includeExternal": false,
  "filterDefaultNames": true
}
```

### Symbol List Response with Pagination
```json
[
  {
    "startIndex": 0,
    "requestedCount": 200,
    "actualCount": 200,
    "nextStartIndex": 200,
    "totalProcessed": 1250,
    "includeExternal": false,
    "filterDefaultNames": true
  },
  {
    "name": "main",
    "address": "0x00401000",
    "namespace": "Global",
    "id": 12345,
    "symbolType": "Function",
    "isPrimary": true,
    "isExternal": false,
    "isFunction": true
  }
]
```

### Label Creation Response (mode='create_label')
```json
{
  "success": true,
  "labelName": "my_label",
  "address": "0x00401000",
  "isPrimary": true
}
```

### Rename Data Response (mode='rename_data')
```json
{
  "success": true,
  "oldName": "DAT_00402000",
  "newName": "my_data",
  "address": "0x00402000"
}
```

## Pagination Implementation

### Pagination Parameters
```java
// Extract pagination from request with backward compatibility
int startIndex = getOptionalInt(request, "start_index", 
    getOptionalInt(request, "offset", 0));
int maxCount = getOptionalInt(request, "max_count",
    getOptionalInt(request, "limit", 200));

// Manual pagination tracking
AtomicInteger currentIndex = new AtomicInteger(0);
symbolIterator.forEach(symbol -> {
    int index = currentIndex.getAndIncrement();
    
    // Skip before start index
    if (index < startIndex) {
        return;
    }
    
    // Stop after max count
    if (symbolData.size() >= maxCount) {
        return;
    }
    
    // Process symbol
    symbolData.add(createSymbolInfo(symbol));
});
```

### Pagination Metadata
```java
// Create pagination info for response
Map<String, Object> paginationInfo = new HashMap<>();
paginationInfo.put("startIndex", startIndex);
paginationInfo.put("requestedCount", maxCount);
paginationInfo.put("actualCount", symbolData.size());
paginationInfo.put("nextStartIndex", startIndex + symbolData.size());
paginationInfo.put("totalProcessed", currentIndex.get());
paginationInfo.put("includeExternal", includeExternal);
paginationInfo.put("filterDefaultNames", filterDefaultNames);
```

## Testing Considerations

### Symbol Table Test Patterns
```java
@Test
public void testSymbolRetrieval() throws Exception {
    // Setup test symbols in transaction
    int txId = program.startTransaction("Create Test Symbols");
    try {
        SymbolTable symbolTable = program.getSymbolTable();
        symbolTable.createLabel(testAddr, "test_symbol", 
            program.getGlobalNamespace(), SourceType.USER_DEFINED);
    } finally {
        program.endTransaction(txId, true);
    }
    
    // Test symbol retrieval via MCP
    CallToolResult result = client.callTool(new CallToolRequest(
        "manage_symbols",
        Map.of("programPath", programPath, "mode", "symbols", "max_count", 50)
    ));
    
    assertFalse("Tool should not have errors", result.isError());
    
    // Validate symbol data in response
    JsonNode jsonResult = objectMapper.readTree(content.text());
    assertTrue("Should find created symbol", 
        jsonResult.toString().contains("test_symbol"));
}
```

### Symbol Creation Validation
```java
// Verify symbol was actually created in program
SymbolTable symbolTable = program.getSymbolTable();
Symbol createdSymbol = symbolTable.getPrimarySymbol(testAddr);
assertNotNull("Symbol should exist", createdSymbol);
assertEquals("Symbol name should match", "test_symbol", createdSymbol.getName());
assertEquals("Should be user-defined", SourceType.USER_DEFINED, createdSymbol.getSource());
```

### External Symbol Testing
```java
// Test external symbol filtering
CallToolResult result = client.callTool(new CallToolRequest(
    "manage_symbols",
    Map.of(
        "programPath", programPath,
        "mode", "symbols",
        "include_external", false,
        "max_count", 100
    )
));

// Verify no external symbols in response
JsonNode jsonResult = objectMapper.readTree(content.text());
for (JsonNode symbolNode : jsonResult) {
    if (symbolNode.has("isExternal")) {
        assertFalse("Should not include external symbols", 
            symbolNode.get("isExternal").asBoolean());
    }
}
```

## Error Handling Patterns

### Common Error Scenarios
```java
try {
    // Symbol operations
} catch (IllegalArgumentException e) {
    return createErrorResult("Invalid parameter: " + e.getMessage());
} catch (ProgramValidationException e) {
    return createErrorResult("Program validation failed: " + e.getMessage());
} catch (Exception e) {
    return createErrorResult("Error in symbol operation: " + e.getMessage());
}
```

### Transaction Error Handling
```java
int transactionID = program.startTransaction("Symbol Operation");
boolean success = false;

try {
    // Perform symbol modifications
    success = true;
} catch (Exception e) {
    // Log error and return failure
    return createErrorResult("Transaction failed: " + e.getMessage());
} finally {
    // Always end transaction with success flag
    program.endTransaction(transactionID, success);
}
```

## Key APIs and Utilities

### Essential Symbol APIs
- `SymbolTable.getAllSymbols(boolean)` - Get all symbols iterator
- `SymbolTable.createLabel(Address, String, Namespace, SourceType)` - Create labels
- `SymbolTable.getPrimarySymbol(Address)` - Get primary symbol at address
- `SymbolTable.getSymbols(Address)` - Get all symbols at address
- `Symbol.setPrimary()` - Set symbol as primary
- `Symbol.getParentNamespace()` - Get symbol namespace

### Utility Functions
- `AddressUtil.formatAddress(Address)` - Consistent address formatting
- `SymbolUtil.isDefaultSymbolName(String)` - Check for default names
- `AbstractToolProvider.getPaginationParams()` - Extract pagination
- `AbstractToolProvider.createJsonResult()` - Format JSON responses

## Important Notes

- Always use transactions when modifying symbols
- Use `SourceType.USER_DEFINED` for user-created symbols
- Filter default names unless specifically requested
- Handle external symbols separately based on user preference
- Validate symbol names before creation
- Use consistent address formatting with `AddressUtil.formatAddress()`
- Implement proper pagination for large symbol tables
- Include comprehensive metadata in symbol responses
- Handle namespace hierarchy properly
- Test both symbol creation and retrieval scenarios
