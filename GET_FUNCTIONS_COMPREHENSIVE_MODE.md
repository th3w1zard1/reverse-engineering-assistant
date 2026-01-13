# get-functions Comprehensive Mode Implementation

## Overview

Instead of adding a new mode to `list-functions`, we're making `get-functions` more powerful by making the `identifier` parameter optional. When `identifier` is omitted, `get-functions` returns ALL functions with comprehensive details.

## Implementation Requirements

### 1. Make `identifier` Optional

**Location:** `src/main/java/reva/tools/decompiler/DecompilerToolProvider.java` (or wherever `get-functions` is implemented)

**Change:**
- `identifier` parameter should be **optional** (not required)
- When `identifier` is `null`, `undefined`, or not provided, trigger comprehensive mode
- When `identifier` is provided, work as before (single or batch function retrieval)

### 2. Comprehensive Mode Behavior

When `identifier` is omitted:

1. **Collect ALL functions** (no pagination limits)
2. **Support multi-program:** Accept `programPath` as string OR array
3. **Return comprehensive data** for each function:
   - name, address, signature, parameters, return type
   - local variables, call count, reference count
   - optionally decompiled code (if `include_decompilation=true`)
4. **Run signature scanning** if `run_signature_scanning=true`
5. **Include undefined functions** if `include_undefined_functions=true`

### 3. New Parameters (Only Used When identifier is Omitted)

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

### 4. Response Structure

**When `identifier` is provided (existing behavior):**
```json
{
  "success": true,
  "function": {
    "name": "main",
    "address": "0x401000",
    "decompiledCode": "...",
    ...
  }
}
```

**When `identifier` is omitted (comprehensive mode):**
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
          "localVariables": [...],
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

### 5. Code Structure

```java
public String handleGetFunctions(Map<String, Object> args) {
    Object identifierObj = args.get("identifier");
    
    // Check if identifier is provided
    if (identifierObj == null || 
        (identifierObj instanceof String && ((String) identifierObj).isEmpty())) {
        // Comprehensive mode - return all functions
        return handleComprehensiveMode(args);
    }
    
    // Existing behavior - single or batch function retrieval
    return handleSingleOrBatchFunctions(identifierObj, args);
}

private String handleComprehensiveMode(Map<String, Object> args) {
    // Get program(s)
    Object programPathObj = args.get("programPath");
    List<Program> programs = getPrograms(programPathObj);  // Handles string or array
    
    // Get comprehensive mode parameters
    boolean includeSignatures = getOptionalBoolean(args, "include_signatures", true);
    boolean includeDecompilation = getOptionalBoolean(args, "include_decompilation", false);
    boolean runSignatureScanning = getOptionalBoolean(args, "run_signature_scanning", false);
    boolean includeUndefined = getOptionalBoolean(args, "include_undefined_functions", 
                                                   runSignatureScanning);
    
    List<Map<String, Object>> programResults = new ArrayList<>();
    
    for (Program program : programs) {
        // Run signature scanning if requested
        if (runSignatureScanning) {
            runSignatureScanning(program);
        }
        
        // Collect all functions
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
        
        Map<String, Object> programResult = new HashMap<>();
        programResult.put("programPath", program.getDomainFile().getPathname());
        programResult.put("totalFunctions", functionData.size());
        programResult.put("functions", functionData);
        if (undefinedFunctions != null) {
            programResult.put("undefinedFunctions", undefinedFunctions);
        }
        programResults.add(programResult);
    }
    
    // Build aggregated response
    Map<String, Object> result = new HashMap<>();
    result.put("success", true);
    result.put("mode", "comprehensive");
    result.put("programs", programResults);
    
    // Add summary
    int totalFunctions = programResults.stream()
        .mapToInt(p -> (Integer) p.get("totalFunctions"))
        .sum();
    result.put("summary", Map.of(
        "totalPrograms", programs.size(),
        "totalFunctions", totalFunctions
    ));
    
    return createJsonResult(result);
}
```

### 6. Schema Update

Update the tool schema to make `identifier` optional:

```java
Map<String, Object> properties = new HashMap<>();
properties.put("programPath", Map.of(
    "type", "string",
    "description", "Path to the program (or array for multi-program)"
));
properties.put("identifier", Map.of(
    "type", "string",
    "description", "Function name or address. Omit for comprehensive mode (all functions)."
));
// ... other properties

List<String> required = new ArrayList<>();  // identifier is NOT required
```

### 7. Multi-Program Support

Handle `programPath` as string or array:

```java
private List<Program> getPrograms(Object programPathObj) {
    List<Program> programs = new ArrayList<>();
    
    if (programPathObj == null) {
        // Use current program in GUI mode
        Program current = getCurrentProgram();
        if (current != null) {
            programs.add(current);
        }
        return programs;
    }
    
    if (programPathObj instanceof List) {
        // Array of program paths
        List<String> paths = (List<String>) programPathObj;
        for (String path : paths) {
            Program program = getValidatedProgram(path);
            programs.add(program);
        }
    } else if (programPathObj instanceof String) {
        // Single program path
        Program program = getValidatedProgram((String) programPathObj);
        programs.add(program);
    }
    
    return programs;
}
```

## Benefits

1. **Single tool for all function operations** - no need for separate comprehensive mode
2. **Intuitive API** - omit identifier to get all functions
3. **Backward compatible** - existing calls with identifier still work
4. **Clear intent** - `get-functions` without identifier = "get all functions"
5. **Efficient** - one call instead of thousands

## Usage Examples

**Get all functions (comprehensive mode):**
```json
{
  "programPath": ["/swkotor.exe", "/swkotor2.exe", "/swkotor2_aspyr.exe"],
  "run_signature_scanning": true,
  "include_signatures": true
}
```

**Get specific function (existing behavior):**
```json
{
  "identifier": "main",
  "view": "decompile"
}
```

**Get multiple functions (batch - existing behavior):**
```json
{
  "identifier": ["main", "0x401000", "encrypt_data"],
  "view": "info"
}
```

## Testing

1. Test with identifier provided (existing behavior)
2. Test with identifier omitted (comprehensive mode)
3. Test with single program
4. Test with multiple programs (array)
5. Test signature scanning integration
6. Test with 10,000+ functions (performance)
