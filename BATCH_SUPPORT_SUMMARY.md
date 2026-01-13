# Batch Support Implementation Summary

This document summarizes the batch/bulk functionality added to ReVa tools, allowing single tool calls to process multiple items efficiently.

## Overview

Batch support has been **implicitly** added to several tools - meaning they accept either a single value or an array of values without changing the tool's behavior or API. This allows LLMs to batch operations naturally when processing multiple items.

## Tools with Batch Support

### 1. `get-functions` (formerly `get-function`)
**Parameter:** `identifier`  
**Supports:** Single function name/address or array of function names/addresses  
**Modes:** All view modes (`decompile`, `disassemble`, `info`, `calls`)  
**Example:**
```json
{
  "identifier": ["main", "0x401000", "encrypt_data"],
  "view": "decompile"
}
```

### 2. `get-references`
**Parameter:** `target`  
**Supports:** Single target or array of targets (addresses, symbols, function names, import names)  
**Modes:** All reference modes (`to`, `from`, `both`, `function`, `referencers_decomp`, `import`, `thunk`)  
**Example:**
```json
{
  "target": ["main", "0x401234", "printf"],
  "mode": "to"
}
```

### 3. `get-call-graph`
**Parameter:** `function_identifier`  
**Supports:** Single function name/address or array of function names/addresses  
**Modes:** `graph`, `tree`, `callers`, `callees`, `callers_decomp` (batch not applicable to `common_callers`)  
**Example:**
```json
{
  "function_identifier": ["main", "encrypt", "decrypt"],
  "mode": "graph",
  "depth": 2
}
```

### 4. `manage-function-tags`
**Parameter:** `function`  
**Supports:** Single function name/address or array of function names/addresses  
**Modes:** `get`, `set`, `add`, `remove` (batch not applicable to `list`)  
**Note:** `get` mode is read-only (no transaction), while `set`/`add`/`remove` use a single transaction for all functions  
**Example:**
```json
{
  "function": ["main", "encrypt", "decrypt"],
  "mode": "add",
  "tags": ["crypto", "important"]
}
```

### 5. `manage-data-types`
**Parameter:** `address_or_symbol` (for `action='apply'` only)  
**Supports:** Single address/symbol or array of addresses/symbols  
**Action:** `apply` (batch support only for apply action)  
**Example:**
```json
{
  "action": "apply",
  "data_type_string": "int",
  "address_or_symbol": ["0x401000", "0x401004", "buffer"]
}
```

### 6. `manage-structures`
**Parameter:** `address_or_symbol` (for `action='apply'` only)  
**Supports:** Single address/symbol or array of addresses/symbols  
**Action:** `apply` (batch support only for apply action)  
**Example:**
```json
{
  "action": "apply",
  "structure_name": "MyStruct",
  "address_or_symbol": ["0x401000", "0x401020", "buffer"],
  "clear_existing": true
}
```

### 7. `manage-comments` (already had batch support)
**Parameter:** `comments` (array of comment objects)  
**Action:** `set`  
**Example:**
```json
{
  "action": "set",
  "comments": [
    {"address": "0x401000", "comment": "Entry point", "comment_type": "eol"},
    {"address": "0x401010", "comment": "Initialization", "comment_type": "eol"}
  ]
}
```

### 8. `manage-bookmarks` (already had batch support)
**Parameter:** `bookmarks` (array of bookmark objects)  
**Action:** `set`  
**Example:**
```json
{
  "action": "set",
  "bookmarks": [
    {"address": "0x401000", "type": "Note", "category": "analysis", "comment": "Important"},
    {"address": "0x401010", "type": "Warning", "category": "analysis", "comment": "Suspicious"}
  ]
}
```

## Implementation Pattern

All batch implementations follow a consistent pattern:

1. **Schema Definition:** Use `oneOf` to allow string or array type
   ```java
   Map<String, Object> property = new HashMap<>();
   property.put("oneOf", List.of(
       Map.of("type", "string"),
       arraySchema
   ));
   ```

2. **Detection:** Check if parameter is `instanceof List`
   ```java
   Object value = request.arguments().get("parameter");
   if (value instanceof List) {
       return handleBatchOperation(program, request, (List<?>) value);
   }
   ```

3. **Processing:** Loop through items, collect results and errors
   ```java
   for (int i = 0; i < itemList.size(); i++) {
       try {
           // Process item
           results.add(itemResult);
       } catch (Exception e) {
           errors.add(Map.of("index", i, "error", e.getMessage()));
       }
   }
   ```

4. **Response Format:**
   ```json
   {
     "success": true,
     "total": 10,
     "succeeded": 8,
     "failed": 2,
     "results": [...],
     "errors": [...]
   }
   ```

## Benefits

- **Implicit Support:** Tools work with single values or arrays without API changes
- **Backward Compatible:** Single values still work exactly as before
- **Efficient:** Batch operations use single transactions where appropriate
- **Error Resilient:** Per-item errors don't fail the entire batch
- **Intuitive:** LLMs can naturally batch operations when processing multiple items

## Tools Not Yet Enhanced (Potential Future Work)

These tools accept single identifiers but haven't been enhanced yet:
- `analyze-data-flow` (`function_address` parameter) - Less useful for batch since each analysis is function-specific
- `analyze-vtables` (`vtable_address`, `function_address` parameters) - Could be useful for batch vtable analysis

These could be enhanced in the future if batch operations prove useful for those use cases.

## Testing Notes

- All batch implementations maintain backward compatibility
- Single value operations work exactly as before
- Batch operations return structured JSON with success/error tracking
- Transactions are used appropriately (single transaction for batch modifications)
