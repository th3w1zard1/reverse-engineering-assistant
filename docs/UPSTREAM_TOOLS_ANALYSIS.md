# Upstream Tools Analysis

This document identifies tools from upstream that we need to add (disabled) to minimize merge conflicts and keep our fork in sync.

## Current Status

### Tool Providers Registered in Upstream
Upstream registers these tool providers in `McpServerManager.initializeToolProviders()`:

1. ✅ `SymbolToolProvider` - **ACTIVE** (we have it)
2. ✅ `StringToolProvider` - **ACTIVE** (we have it)
3. ✅ `FunctionToolProvider` - **ACTIVE** (we have it)
4. ✅ `DataToolProvider` - **ACTIVE** (we have it, was restored)
5. ✅ `DecompilerToolProvider` - **ACTIVE** (we have it)
6. ✅ `MemoryToolProvider` - **ACTIVE** (we have it)
7. ✅ `ProjectToolProvider` - **ACTIVE** (we have it)
8. ✅ `CrossReferencesToolProvider` - **ACTIVE** (we have it)
9. ✅ `DataTypeToolProvider` - **ACTIVE** (we have it)
10. ✅ `StructureToolProvider` - **ACTIVE** (we have it)
11. ✅ `CommentToolProvider` - **ACTIVE** (we have it)
12. ✅ `BookmarkToolProvider` - **ACTIVE** (we have it)
13. ✅ `ImportExportToolProvider` - **ACTIVE** (we have it, was disabled)
14. ✅ `DataFlowToolProvider` - **ACTIVE** (we have it)
15. ✅ `CallGraphToolProvider` - **ACTIVE** (we have it)
16. ✅ `ConstantSearchToolProvider` - **ACTIVE** (we have it)
17. ✅ `VtableToolProvider` - **ACTIVE** (we have it)

### Tool Providers We Have But Upstream Doesn't
1. `GetFunctionToolProvider` - **OUR ADDITION** (not in upstream)
2. `SuggestionToolProvider` - **OUR ADDITION** (not in upstream)

## Required Changes

### 1. Register ImportExportToolProvider (but keep tools disabled)

**Current State:**
- File exists: `src/main/java/reva/tools/imports/ImportExportToolProvider.java` ✅
- File is disabled (tools commented out) ✅
- **IS registered in McpServerManager** ✅

**Upstream State:**
- File exists ✅
- Tools are active ✅
- **IS registered in McpServerManager** ✅

**Action Required:**
Add `ImportExportToolProvider` to `McpServerManager.initializeToolProviders()` but keep the tools disabled in the provider itself:

```java
// In McpServerManager.java
toolProviders.add(new ImportExportToolProvider(server));  // Add this line
```

The provider already has its `registerTools()` method with all tools commented out, so registering it won't actually register any tools.

### 2. Tools in ProjectToolProvider

**Upstream has:**
- `open-project` - **DISABLED in our code** (merged into `open`)
- `open-program` - **DISABLED in our code** (merged into `open`)
- `open` - **DOES NOT EXIST in upstream** (our addition)

**Our code has:**
- `open` - **ACTIVE** (our unified tool)
- `open-project` - **DISABLED** (kept for compatibility) ✅
- `open-program` - **DISABLED** (kept for compatibility) ✅
- `export` - **ACTIVE** (our addition, not in upstream)

**Status:** ✅ Already handled correctly - disabled tools are present

### 3. Tools in ImportExportToolProvider

**Upstream registers:**
1. `list-imports` - **DISABLED in our code** ✅
2. `list-exports` - **DISABLED in our code** ✅
3. `find-import-references` - **DISABLED in our code** ✅
4. `resolve-thunk` - **DISABLED in our code** ✅

**Our code:**
- All tools are disabled (commented out in `registerTools()`) ✅
- Provider is not registered in `McpServerManager` ❌

**Action Required:**
- Register the provider in `McpServerManager` (tools will remain disabled)

## Summary of Missing Registrations

### In McpServerManager.java

**Missing:**
```java
toolProviders.add(new ImportExportToolProvider(server));
```

**Already Present (but should verify):**
- All other tool providers match upstream ✅

**Extra (our additions):**
```java
toolProviders.add(new GetFunctionToolProvider(server));
toolProviders.add(new reva.tools.suggestions.SuggestionToolProvider(server));
```

## Implementation Plan

1. ✅ **ImportExportToolProvider file** - Already exists and is disabled
2. ✅ **Register ImportExportToolProvider** - **COMPLETED** - Added to `McpServerManager.initializeToolProviders()`
3. ✅ **Disabled tools in ProjectToolProvider** - Already present (`open-project`, `open-program`)
4. ✅ **Disabled tools in ImportExportToolProvider** - Already present (all 4 tools)

## Verification Checklist

- [x] `ImportExportToolProvider` is added to `McpServerManager.initializeToolProviders()` ✅ **COMPLETED**
- [x] All disabled tool methods exist in `ProjectToolProvider` (verified ✅)
- [x] All disabled tool methods exist in `ImportExportToolProvider` (verified ✅)
- [x] `DataToolProvider` is registered (verified ✅ - was restored)
- [x] Our custom providers (`GetFunctionToolProvider`, `SuggestionToolProvider`) remain registered

## Expected Diff Reduction

By registering `ImportExportToolProvider` (even though tools are disabled), we will:
1. Match upstream's tool provider registration structure
2. Reduce merge conflicts in `McpServerManager.java`
3. Maintain our customizations (disabled tools, new unified `open` tool)
4. Keep compatibility with upstream for easier merging

## Notes

- The `ImportExportToolProvider` tools are functionally merged into `SymbolToolProvider.manage-symbols` with modes `imports` and `exports`
- The `open-project` and `open-program` tools are functionally merged into the unified `open` tool
- All disabled tools are kept for reference and upstream compatibility
- Our additions (`GetFunctionToolProvider`, `SuggestionToolProvider`) should remain active
