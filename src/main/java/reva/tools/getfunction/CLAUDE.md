# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the getfunction tools package.

## Package Overview

The `reva.tools.getfunction` package provides MCP tools for retrieving function details in various formats. The primary tool `get_function` supports multiple view modes: decompiled code, assembly/disassembly, function metadata, and call analysis. This tool is designed for quick function inspection and complements the more comprehensive decompiler tools package.

## Key Tool

### `get_function`
Get function details in various formats: decompiled code, assembly, function information, or internal calls.

**Parameters:**
- `programPath` (string, required) - Path in the Ghidra Project to the program
- `identifier` (string, required) - Function name or address (e.g., 'main' or '0x401000')
- `view` (string, optional) - View mode: 'decompile', 'disassemble', 'info', 'calls' (default: 'decompile')
- `offset` (integer, optional) - Line number to start reading from when view='decompile' (1-based, default: 1)
- `limit` (integer, optional) - Number of lines to return when view='decompile' (default: 50)
- `include_callers` (boolean, optional) - Include list of functions that call this one when view='decompile' (default: false)
- `include_callees` (boolean, optional) - Include list of functions this one calls when view='decompile' (default: false)
- `include_comments` (boolean, optional) - Whether to include comments in the decompilation when view='decompile' (default: false)
- `include_incoming_references` (boolean, optional) - Whether to include incoming cross references when view='decompile' (default: true)
- `include_reference_context` (boolean, optional) - Whether to include code context snippets from calling functions when view='decompile' (default: true)

## Function Resolution

The `get_function` tool supports flexible function identification through the `resolveFunction()` method:

```java
private Function resolveFunction(Program program, String identifier) {
    // 1. Try as address or symbol first
    Address address = AddressUtil.resolveAddressOrSymbol(program, identifier);
    if (address != null) {
        Function function = AddressUtil.getContainingFunction(program, address);
        if (function != null) {
            return function;
        }
        // 2. Try undefined function for addresses without defined functions
        try {
            TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS);
            return UndefinedFunction.findFunction(program, address, monitor);
        } catch (CancelledException e) {
            // Timeout, continue to name lookup
        }
    }

    // 3. Try as function name (case-insensitive)
    FunctionManager functionManager = program.getFunctionManager();
    FunctionIterator functions = functionManager.getFunctions(true);
    while (functions.hasNext()) {
        Function f = functions.next();
        if (f.getName().equals(identifier) || f.getName().equalsIgnoreCase(identifier)) {
            return f;
        }
    }

    return null;
}
```

**Resolution order:**
1. Address/symbol resolution (handles addresses like "0x401000" and symbol names)
2. Undefined function lookup (for addresses with code but no defined function)
3. Function name matching (case-insensitive exact match)

## View Modes

### 1. Decompile View (Default)
Returns decompiled C code with optional enhancements.

**Response format:**
```json
{
  "function": "main",
  "address": "0x00401000",
  "programName": "example.exe",
  "decompilation": "   1\tint main(int argc, char **argv) {\n...",
  "totalLines": 45,
  "offset": 1,
  "limit": 50,
  "decompSignature": "int main(int argc, char **argv)",
  "incomingReferences": [...],  // If include_incoming_references=true
  "totalIncomingReferences": 5,
  "comments": [...],  // If include_comments=true
  "callers": [...],   // If include_callers=true
  "callees": [...]    // If include_callees=true
}
```

**Key features:**
- Line-numbered decompilation output (1-based line numbers)
- Line range support via `offset` and `limit` parameters
- Optional incoming references with code context
- Optional function comments (all types: pre, eol, post, plate, repeatable)
- Optional caller/callee lists
- Decompilation signature metadata

**Implementation pattern:**
```java
private McpSchema.CallToolResult handleDecompileView(Program program, Function function, CallToolRequest request) {
    // Extract parameters
    int offset = getOptionalInt(request, "offset", 1);
    int limit = getOptionalInt(request, "limit", 50);
    boolean includeCallers = getOptionalBoolean(request, "include_callers", false);
    boolean includeCallees = getOptionalBoolean(request, "include_callees", false);
    boolean includeComments = getOptionalBoolean(request, "include_comments", false);
    boolean includeIncomingReferences = getOptionalBoolean(request, "include_incoming_references", true);
    boolean includeReferenceContext = getOptionalBoolean(request, "include_reference_context", true);

    // Create decompiler and decompile
    DecompInterface decompiler = createConfiguredDecompiler(program);
    try {
        TaskMonitor monitor = createTimeoutMonitor();
        DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);
        
        if (monitor.isCancelled()) {
            return createErrorResult("Decompilation timed out");
        }
        
        if (!decompileResults.decompileCompleted()) {
            return createErrorResult("Decompilation failed: " + decompileResults.getErrorMessage());
        }

        // Get synchronized content with options
        Map<String, Object> syncedContent = getSynchronizedContent(
            program, markup, decompiledFunction.getC(),
            offset, limit, false, includeComments,
            includeIncomingReferences, includeReferenceContext, function);
        
        // Add caller/callee info if requested
        // ...
    } finally {
        decompiler.dispose(); // CRITICAL - prevents memory leaks
    }
}
```

### 2. Disassemble View
Returns assembly instructions for the function body.

**Response format:**
```json
{
  "function": "main",
  "address": "0x00401000",
  "instructions": [
    {
      "address": "0x00401000",
      "instruction": "PUSH EBP",
      "comment": "Function prologue"  // If comment exists
    },
    ...
  ]
}
```

**Implementation pattern:**
```java
private McpSchema.CallToolResult handleDisassembleView(Program program, Function function) {
    List<Map<String, Object>> instructions = new ArrayList<>();
    Listing listing = program.getListing();

    for (Instruction instr : listing.getInstructions(function.getBody(), true)) {
        Map<String, Object> instrData = new HashMap<>();
        instrData.put("address", AddressUtil.formatAddress(instr.getMinAddress()));
        instrData.put("instruction", instr.toString());
        
        String comment = listing.getComment(instr.getMinAddress(), 0);
        if (comment != null && !comment.isEmpty()) {
            instrData.put("comment", comment);
        }
        
        instructions.add(instrData);
    }
    // ...
}
```

### 3. Info View
Returns function metadata and structure information.

**Response format:**
```json
{
  "name": "main",
  "address": "0x00401000",
  "returnType": "int",
  "callingConvention": "__cdecl",
  "isExternal": false,
  "isThunk": false,
  "parameters": [
    {
      "name": "argc",
      "dataType": "int",
      "ordinal": 0
    },
    ...
  ],
  "localVariables": [
    {
      "name": "local_var",
      "dataType": "char*"
    },
    ...
  ],
  "startAddress": "0x00401000",
  "endAddress": "0x004010FF",
  "sizeInBytes": 256
}
```

**Implementation pattern:**
```java
private McpSchema.CallToolResult handleInfoView(Program program, Function function) {
    Map<String, Object> info = new HashMap<>();
    info.put("name", function.getName());
    info.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
    info.put("returnType", function.getReturnType().toString());
    info.put("callingConvention", function.getCallingConventionName());
    info.put("isExternal", function.isExternal());
    info.put("isThunk", function.isThunk());

    // Parameters with ordinals
    List<Map<String, Object>> parameters = new ArrayList<>();
    for (int i = 0; i < function.getParameterCount(); i++) {
        Parameter param = function.getParameter(i);
        Map<String, Object> paramInfo = new HashMap<>();
        paramInfo.put("name", param.getName());
        paramInfo.put("dataType", param.getDataType().toString());
        paramInfo.put("ordinal", i);
        parameters.add(paramInfo);
    }
    info.put("parameters", parameters);

    // Local variables
    List<Map<String, Object>> locals = new ArrayList<>();
    for (var local : function.getLocalVariables()) {
        Map<String, Object> localInfo = new HashMap<>();
        localInfo.put("name", local.getName());
        localInfo.put("dataType", local.getDataType().toString());
        locals.add(localInfo);
    }
    info.put("localVariables", locals);

    // Function body info
    var body = function.getBody();
    if (body != null && body.getMaxAddress() != null) {
        info.put("startAddress", AddressUtil.formatAddress(function.getEntryPoint()));
        info.put("endAddress", AddressUtil.formatAddress(body.getMaxAddress()));
        info.put("sizeInBytes", body.getNumAddresses());
    }
    // ...
}
```

### 4. Calls View
Returns all function calls made within the function body.

**Response format:**
```json
{
  "function": "main",
  "address": "0x00401000",
  "calls": [
    {
      "address": "0x00401020",
      "calledFunction": "printf",
      "calledAddress": "0x00405000"
    },
    ...
  ]
}
```

**Implementation pattern:**
```java
private McpSchema.CallToolResult handleCallsView(Program program, Function function) {
    List<Map<String, Object>> calls = new ArrayList<>();
    Listing listing = program.getListing();

    for (Instruction instr : listing.getInstructions(function.getBody(), true)) {
        Address[] flowDestinations = instr.getFlows();
        for (Address dest : flowDestinations) {
            Function calledFunc = program.getFunctionManager().getFunctionAt(dest);
            if (calledFunc != null) {
                Map<String, Object> callInfo = new HashMap<>();
                callInfo.put("address", AddressUtil.formatAddress(instr.getMinAddress()));
                callInfo.put("calledFunction", calledFunc.getName());
                callInfo.put("calledAddress", AddressUtil.formatAddress(dest));
                calls.add(callInfo);
            }
        }
    }
    // ...
}
```

## Decompiler Integration

### Decompiler Lifecycle Management
**Always dispose DecompInterface instances** to prevent memory leaks:

```java
DecompInterface decompiler = createConfiguredDecompiler(program);
try {
    // Use decompiler
    DecompileResults decompileResults = decompiler.decompileFunction(function, 0, monitor);
    // Process results...
} finally {
    decompiler.dispose(); // CRITICAL
}
```

### Decompiler Configuration
```java
private DecompInterface createConfiguredDecompiler(Program program) {
    DecompInterface decompiler = new DecompInterface();
    decompiler.toggleCCode(true);
    decompiler.toggleSyntaxTree(true);
    decompiler.setSimplificationStyle("decompile");

    if (!decompiler.openProgram(program)) {
        logError("Failed to initialize decompiler for " + program.getName());
        decompiler.dispose();
        return null;
    }
    return decompiler;
}
```

### Timeout Management
```java
private TaskMonitor createTimeoutMonitor() {
    ConfigManager configManager = RevaInternalServiceRegistry.getService(ConfigManager.class);
    int timeoutSeconds = configManager != null ? configManager.getDecompilerTimeoutSeconds() : 60;
    return TimeoutTaskMonitor.timeoutIn(timeoutSeconds, TimeUnit.SECONDS);
}
```

**Check for timeouts:**
```java
if (monitor.isCancelled()) {
    return createErrorResult("Decompilation timed out after " + getTimeoutSeconds() + " seconds");
}
```

## Synchronized Content Pattern

The `getSynchronizedContent()` method handles line range extraction, comment inclusion, and incoming references:

```java
private Map<String, Object> getSynchronizedContent(
        Program program,
        ClangTokenGroup markup,
        String fullDecompCode,
        int offset,
        Integer limit,
        boolean includeDisassembly,  // Not used in get_function
        boolean includeComments,
        boolean includeIncomingReferences,
        boolean includeReferenceContext,
        Function function) {
    Map<String, Object> result = new HashMap<>();

    // Convert markup to lines for synchronization
    List<ClangLine> clangLines = DecompilerUtils.toLines(markup);
    String[] decompLines = fullDecompCode.split("\n");

    // Calculate line range (offset is 1-based)
    int totalLines = decompLines.length;
    int startIdx = Math.max(0, offset - 1); // Convert to 0-based
    int endIdx = limit != null ? Math.min(totalLines, startIdx + limit) : totalLines;

    result.put("totalLines", totalLines);
    result.put("offset", offset);
    if (limit != null) {
        result.put("limit", limit);
    }

    // Include incoming references if requested
    if (includeIncomingReferences) {
        int maxIncomingRefs = 10;
        List<Map<String, Object>> incomingRefs = 
            DecompilationContextUtil.getEnhancedIncomingReferences(
                program, function, includeReferenceContext, maxIncomingRefs);
        if (!incomingRefs.isEmpty()) {
            result.put("incomingReferences", incomingRefs);
            // Include total count and limit message if applicable
        }
    }

    // Build line-numbered decompilation output
    StringBuilder rangedDecomp = new StringBuilder();
    for (int i = startIdx; i < endIdx; i++) {
        rangedDecomp.append(String.format("%4d\t%s\n", i + 1, decompLines[i]));
    }
    result.put("decompilation", rangedDecomp.toString());

    // Include all comments if requested
    if (includeComments) {
        List<Map<String, Object>> functionComments = getAllCommentsInFunction(program, function);
        if (!functionComments.isEmpty()) {
            result.put("comments", functionComments);
        }
    }

    return result;
}
```

### Comment Collection
All comment types are supported:

```java
private static final Map<CommentType, String> COMMENT_TYPE_NAMES = Map.of(
    CommentType.PRE, "pre",
    CommentType.EOL, "eol",
    CommentType.POST, "post",
    CommentType.PLATE, "plate",
    CommentType.REPEATABLE, "repeatable"
);

private List<Map<String, Object>> getAllCommentsInFunction(Program program, Function function) {
    List<Map<String, Object>> comments = new ArrayList<>();
    Listing listing = program.getListing();
    var body = function.getBody();

    CodeUnitIterator codeUnits = listing.getCodeUnits(body, true);
    while (codeUnits.hasNext()) {
        CodeUnit cu = codeUnits.next();
        Address addr = cu.getAddress();

        // Check all comment types
        for (Entry<CommentType, String> entry : COMMENT_TYPE_NAMES.entrySet()) {
            String comment = cu.getComment(entry.getKey());
            if (comment != null && !comment.isEmpty()) {
                Map<String, Object> commentInfo = new HashMap<>();
                commentInfo.put("address", AddressUtil.formatAddress(addr));
                commentInfo.put("type", entry.getValue());
                commentInfo.put("comment", comment);
                comments.add(commentInfo);
            }
        }
    }
    return comments;
}
```

### Incoming References Integration
Uses `DecompilationContextUtil.getEnhancedIncomingReferences()` for rich reference context:

```java
import reva.util.DecompilationContextUtil;

int maxIncomingRefs = 10;
int totalRefCount = 0;
var refIterator = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
while (refIterator.hasNext()) {
    refIterator.next();
    totalRefCount++;
}

List<Map<String, Object>> incomingRefs = 
    DecompilationContextUtil.getEnhancedIncomingReferences(
        program, function, includeReferenceContext, maxIncomingRefs);

if (!incomingRefs.isEmpty()) {
    result.put("incomingReferences", incomingRefs);
    result.put("totalIncomingReferences", totalRefCount);

    if (totalRefCount > maxIncomingRefs) {
        result.put("incomingReferencesLimited", true);
        result.put("incomingReferencesMessage", String.format(
            "Showing first %d of %d references. Use 'get_references' tool with target='%s' and mode='to' to see all references.",
            maxIncomingRefs, totalRefCount, function.getName()
        ));
    }
}
```

## Caller/Callee Lists

When `include_callers=true` or `include_callees=true`, the tool includes function relationship information:

```java
if (includeCallers) {
    List<Function> callers = new ArrayList<>();
    for (Function caller : function.getCallingFunctions(monitor)) {
        callers.add(caller);
    }
    List<Map<String, Object>> callerInfo = new ArrayList<>();
    for (Function caller : callers) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", caller.getName());
        info.put("address", AddressUtil.formatAddress(caller.getEntryPoint()));
        callerInfo.add(info);
    }
    resultData.put("callers", callerInfo);
}

if (includeCallees) {
    List<Function> callees = new ArrayList<>();
    for (Function callee : function.getCalledFunctions(monitor)) {
        callees.add(callee);
    }
    List<Map<String, Object>> calleeInfo = new ArrayList<>();
    for (Function callee : callees) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", callee.getName());
        info.put("address", AddressUtil.formatAddress(callee.getEntryPoint()));
        calleeInfo.add(info);
    }
    resultData.put("callees", calleeInfo);
}
```

**Note:** Caller/callee enumeration uses the TaskMonitor and may be subject to timeout limits.

## Error Handling Patterns

### Function Resolution Errors
```java
Function function = resolveFunction(program, identifier);
if (function == null) {
    return createErrorResult("Function not found: " + identifier);
}
```

### Decompilation Errors
```java
if (!decompileResults.decompileCompleted()) {
    return createErrorResult("Decompilation failed: " + decompileResults.getErrorMessage());
}

if (monitor.isCancelled()) {
    return createErrorResult("Decompilation timed out after " + getTimeoutSeconds() + " seconds");
}
```

### Invalid View Mode
```java
switch (view) {
    case "decompile":
        return handleDecompileView(program, function, request);
    case "disassemble":
        return handleDisassembleView(program, function);
    case "info":
        return handleInfoView(program, function);
    case "calls":
        return handleCallsView(program, function);
    default:
        return createErrorResult("Invalid view mode: " + view);
}
```

### Exception Handling
The tool handler is automatically wrapped by `registerTool()` to catch `IllegalArgumentException` and convert to error responses. Additional exceptions should be caught and logged:

```java
registerTool(tool, (exchange, request) -> {
    try {
        // Tool logic
    } catch (IllegalArgumentException e) {
        return createErrorResult(e.getMessage()); // Auto-caught by registerTool, but explicit for clarity
    } catch (Exception e) {
        logError("Error in get_function", e);
        return createErrorResult("Tool execution failed: " + e.getMessage());
    }
});
```

## Response Patterns

### Standard Response Structure
All views return a consistent structure with function identification:

```java
Map<String, Object> resultData = new HashMap<>();
resultData.put("function", function.getName());
resultData.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
resultData.put("programName", program.getName()); // For decompile view
// View-specific data...
return createJsonResult(resultData);
```

### Line-Numbered Output Format
Decompile view uses a specific format for line numbers:

```java
StringBuilder rangedDecomp = new StringBuilder();
for (int i = startIdx; i < endIdx; i++) {
    rangedDecomp.append(String.format("%4d\t%s\n", i + 1, decompLines[i]));
}
// Result: "   1\tint main(int argc, char **argv) {\n   2\t    return 0;\n..."
```

## Testing Considerations

### Test Data Requirements
- Functions with various types (regular, thunk, external)
- Functions with different calling conventions
- Functions with complex parameter lists and local variables
- Functions with comments of all types
- Functions with many callers/callees (test timeout behavior)
- Undefined functions (addresses with code but no defined function)
- Large functions (test line range extraction)

### Integration Tests
- Verify function resolution works for addresses, symbols, and names
- Test all view modes return correct data
- Validate line range extraction accuracy
- Check comment collection includes all types
- Verify incoming references are correctly included with context
- Test timeout handling during decompilation
- Validate caller/callee enumeration accuracy
- Test undefined function resolution
- Verify error messages are helpful and specific

## Utility Dependencies

### AddressUtil
**ALWAYS use AddressUtil for address formatting:**
```java
import reva.util.AddressUtil;

String formatted = AddressUtil.formatAddress(function.getEntryPoint());
Address address = AddressUtil.resolveAddressOrSymbol(program, identifier);
Function function = AddressUtil.getContainingFunction(program, address);
```

### DecompilationContextUtil
**Use for rich reference context:**
```java
import reva.util.DecompilationContextUtil;

List<Map<String, Object>> incomingRefs = 
    DecompilationContextUtil.getEnhancedIncomingReferences(
        program, function, includeReferenceContext, maxRefs);
```

### DecompilerUtils
**Use for markup-to-lines conversion:**
```java
import ghidra.app.decompiler.component.DecompilerUtils;

List<ClangLine> clangLines = DecompilerUtils.toLines(markup);
```

## Important Constants

### Default Values
- `offset`: 1 (first line)
- `limit`: 50 (lines to return)
- `maxIncomingRefs`: 10 (incoming references to include)
- `timeoutSeconds`: 60 (from ConfigManager, default if unavailable)

## Important Notes

- **Memory Management**: Always dispose DecompInterface instances in finally blocks to prevent memory leaks
- **Timeout Handling**: Use createTimeoutMonitor() with configured timeouts for all decompilation operations
- **Address Formatting**: Always use AddressUtil.formatAddress() for consistent address formatting in JSON output
- **Function Resolution**: Supports addresses, symbols, and function names with undefined function fallback
- **Line Numbers**: Decompile view uses 1-based line numbers in output format
- **View Modes**: Four distinct views (decompile, disassemble, info, calls) with view-specific response formats
- **Comments**: Supports all comment types (pre, eol, post, plate, repeatable) when include_comments=true
- **Reference Context**: Uses DecompilationContextUtil for enhanced incoming references with optional code context
- **Caller/Callee Lists**: Optional inclusion via include_callers/include_callees parameters
- **Error Messages**: Provide specific error messages for function resolution failures and decompilation errors
- **Undefined Functions**: Supports decompilation of undefined functions (addresses with code but no defined function)
