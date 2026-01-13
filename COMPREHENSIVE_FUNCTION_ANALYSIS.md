# Comprehensive Function Analysis Implementation Guide

## Problem Statement

AI agents are repeatedly calling `list-functions` and `get-functions` when tasked with comprehensive function analysis across multiple programs. This leads to:
- Hundreds of tool calls
- Inefficient pagination handling
- Poor performance
- Unclear tool selection

## Solution: Make `get-functions` identifier Optional

Instead of adding a new mode to `list-functions`, make the `identifier` parameter in `get-functions` optional. When `identifier` is omitted, `get-functions` returns ALL functions with comprehensive details in a single call.

## Implementation Requirements

### 1. Make `identifier` Optional in `get-functions`

**Location:** `src/main/java/reva/tools/decompiler/DecompilerToolProvider.java` (or wherever `get-functions` is implemented)

**Change:**
- Make `identifier` parameter **optional** (not required)
- When `identifier` is `null`, `undefined`, or not provided → comprehensive mode
- When `identifier` is provided → existing behavior (single or batch function retrieval)

### 2. New Parameters

Add these optional parameters (only used when `identifier` is omitted):

```java
- include_signatures (boolean, default: true)
  Include function signatures/prototypes for each function

- include_decompilation (boolean, default: false)
  Include decompiled code for each function (can be slow)

- run_signature_scanning (boolean, default: false)
  Run Ghidra's signature scanning to discover undefined functions

- include_undefined_functions (boolean, default: true when run_signature_scanning=true)
  Include undefined function candidates in results
```

### 3. Multi-Program Support

**Parameter Change:** `programPath` should accept either:
- Single string: `"programPath": "/swkotor.exe"`
- Array of strings: `"programPath": ["/swkotor.exe", "/swkotor2.exe", "/swkotor2_aspyr.exe"]`

When an array is provided, process all programs and return results grouped by program. This applies when `identifier` is omitted (comprehensive mode).

### 4. Response Structure

**When `identifier` is omitted (comprehensive mode), return:**

```json
{
  "success": true,
  "mode": "comprehensive",
  "programs": [
    {
      "programPath": "/swkotor.exe",
      "totalFunctions": 1234,
      "functions": [
        {
          "name": "main",
          "address": "0x401000",
          "signature": "int main(int argc, char** argv)",
          "returnType": "int",
          "parameters": [
            {"name": "argc", "type": "int", "ordinal": 0},
            {"name": "argv", "type": "char**", "ordinal": 1}
          ],
          "localVariables": [
            {"name": "buffer", "type": "char[256]", "address": "0x401234"}
          ],
          "callCount": 1,
          "referenceCount": 5,
          "decompiledCode": "...",  // Only if include_decompilation=true
          "isExternal": false,
          "hasBody": true
        }
        // ... all other functions
      ],
      "undefinedFunctions": [  // Only if include_undefined_functions=true
        {
          "address": "0x402000",
          "referenceCount": 3,
          "callSites": ["0x401100", "0x401200"]
        }
      ]
    }
    // ... other programs if array provided
  ],
  "summary": {
    "totalPrograms": 3,
    "totalFunctions": 4567,
    "totalUndefinedFunctions": 123
  }
}
```

### 5. Implementation Details

#### Function Collection
- **No pagination limits** - Collect ALL functions internally
- Use `FunctionManager.getFunctions(true)` to get all functions (including external)
- Filter default names if `filter_default_names=true`

#### Signature Information
- Use `Function.getSignature()` to get function signature
- Use `Function.getParameters()` to get parameter details
- Use `Function.getReturnType()` to get return type
- Use `Function.getLocalVariables()` to get local variables

#### Signature Scanning
- Use Ghidra's `FunctionSignatureDB` and `ApplyFunctionSignaturesScript` or similar
- Run signature scanning BEFORE collecting functions to discover new functions
- This should be done in a transaction if it modifies the program

#### Decompilation (Optional)
- Only decompile if `include_decompilation=true`
- Use `DecompInterface` (remember to dispose!)
- Handle decompilation failures gracefully (some functions may not decompile)
- Consider timeouts for large functions

#### Performance Considerations
- For large binaries (1000+ functions), decompilation can be slow
- Consider processing in batches and returning progress updates
- Cache decompilation results if possible
- Warn users if operation will take a long time

### 6. Code Structure

```java
private String handleComprehensiveMode(Map<String, Object> args) {
    // Get program(s) - handles string or array
    List<Program> programs = getPrograms(args.get("programPath"));
    
    for (Program program : programs) {
    boolean includeSignatures = getOptionalBoolean(args, "include_signatures", true);
    boolean includeDecompilation = getOptionalBoolean(args, "include_decompilation", false);
    boolean runSignatureScanning = getOptionalBoolean(args, "run_signature_scanning", false);
    boolean includeUndefined = getOptionalBoolean(args, "include_undefined_functions", 
                                                   runSignatureScanning);
    
    // Run signature scanning if requested
    if (runSignatureScanning) {
        runSignatureScanning(program);
    }
    
    // Collect all functions (no pagination)
    List<Function> allFunctions = collectAllFunctions(program);
    
    // Build comprehensive function data
    List<Map<String, Object>> functionData = new ArrayList<>();
    for (Function func : allFunctions) {
        Map<String, Object> funcInfo = buildFunctionInfo(func, includeSignatures, includeDecompilation);
        functionData.add(funcInfo);
    }
    
    // Collect undefined functions if requested
    List<Map<String, Object>> undefinedFunctions = null;
    if (includeUndefined) {
        undefinedFunctions = findUndefinedFunctions(program);
    }
    
    // Build response
    Map<String, Object> result = new HashMap<>();
    result.put("success", true);
    result.put("mode", "comprehensive");
    result.put("programPath", program.getDomainFile().getPathname());
    result.put("totalFunctions", functionData.size());
    result.put("functions", functionData);
    if (undefinedFunctions != null) {
        result.put("undefinedFunctions", undefinedFunctions);
    }
    
    return createJsonResult(result);
}
```

### 7. Multi-Program Handling

When `programPath` is an array:

```java
if (programPath instanceof List) {
    List<String> programPaths = (List<String>) programPath;
    List<Map<String, Object>> programResults = new ArrayList<>();
    
    for (String path : programPaths) {
        Program program = getValidatedProgram(path);
        Map<String, Object> programResult = handleComprehensiveMode(program, args);
        programResults.add(programResult);
    }
    
    // Aggregate results
    Map<String, Object> aggregated = aggregateResults(programResults);
    return createJsonResult(aggregated);
}
```

### 8. Testing

Create integration tests that:
1. Test single program comprehensive mode
2. Test multi-program comprehensive mode
3. Test with signature scanning enabled
4. Test with decompilation enabled
5. Test with large binaries (1000+ functions)
6. Verify all function details are included
7. Verify undefined functions are discovered

## Migration Path

1. **Phase 1:** Implement `comprehensive` mode for single program
2. **Phase 2:** Add multi-program support
3. **Phase 3:** Add signature scanning integration
4. **Phase 4:** Add optional decompilation
5. **Phase 5:** Update documentation and examples

## Documentation Updates

- ✅ Updated `new_tool_list.md` with comprehensive mode documentation
- ✅ Added usage tips for when to use comprehensive mode
- ⏳ Update developer documentation with implementation details
- ⏳ Add examples to README

## Benefits

1. **Reduced Tool Calls:** One call instead of hundreds
2. **Better Performance:** Internal pagination, optimized collection
3. **Clearer Intent:** Explicit "comprehensive analysis" mode
4. **Multi-Program Support:** Analyze multiple binaries in one call
5. **Signature Scanning:** Integrated discovery of undefined functions
6. **Complete Data:** All function details in one response

## Example Usage

**Before (inefficient):**
```json
// Call 1: Get first 100 functions
{"mode": "all", "max_count": 100, "start_index": 0}
// Call 2: Get next 100 functions
{"mode": "all", "max_count": 100, "start_index": 100}
// ... repeat many times ...
// Then for each function:
{"identifier": "function1", "view": "info"}
{"identifier": "function2", "view": "info"}
// ... repeat for all functions ...
```

**After (efficient):**
```json
// Single call gets everything
{
  "mode": "comprehensive",
  "programPath": ["/swkotor.exe", "/swkotor2.exe", "/swkotor2_aspyr.exe"],
  "run_signature_scanning": true,
  "include_signatures": true,
  "include_undefined_functions": true
}
```
