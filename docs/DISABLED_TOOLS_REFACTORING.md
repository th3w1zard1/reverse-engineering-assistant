# Disabled Tools Refactoring

This document tracks the refactoring of disabled tool logic to ensure active tools reuse the original tool handlers, benefiting from upstream updates.

## Overview

Several tools were disabled/merged but their handlers are kept for upstream compatibility. To ensure we benefit from upstream improvements, we've extracted the handler logic into reusable protected methods that active tools can call directly.

## Refactoring Strategy

1. **Extract Handler Logic**: Move tool handler logic from disabled `register*Tool()` methods into protected handler methods
2. **Make Methods Protected**: Change visibility from `private` to `protected` so other tool providers can access them
3. **Delegate from Active Tools**: Have active tools call the extracted handler methods instead of duplicating logic
4. **Document Dependencies**: Add comments noting that methods should be kept in sync with upstream disabled tool handlers

## Completed Refactorings

### 1. ImportExportToolProvider → SymbolToolProvider

**Disabled Tools:**
- `registerListImportsTool()` → Merged into `manage-symbols` with `mode='imports'`
- `registerListExportsTool()` → Merged into `manage-symbols` with `mode='exports'`
- `registerFindImportReferencesTool()` → Disabled (functionality may be available elsewhere)
- `registerResolveThunkTool()` → Disabled (functionality may be available elsewhere)

**Extracted Methods (protected):**
- `collectImports(Program, String)` - Used by SymbolToolProvider.handleImportsMode()
- `collectExports(Program)` - Used by SymbolToolProvider.handleExportsMode()
- `findImportsByName(Program, String, String)` - Used by handleFindImportReferences()
- `buildThunkMap(Program)` - Used by handleFindImportReferences()
- `collectImportReferences(...)` - Used by handleFindImportReferences()
- `buildThunkChain(Function)` - Used by CrossReferencesToolProvider and handleResolveThunk()
- `buildImportInfo(Function)` - Used by handleFindImportReferences()
- `groupImportsByLibrary(List)` - Used by SymbolToolProvider.handleImportsMode()
- `paginate(List, int, int)` - Used by SymbolToolProvider
- `clamp(int, int, int)` - Used by disabled tool handlers

**Extracted Handler Methods (protected):**
- `handleFindImportReferences(CallToolRequest)` - Extracted from registerFindImportReferencesTool()
- `handleResolveThunk(CallToolRequest)` - Extracted from registerResolveThunkTool()

**Active Tool Integration:**
- `SymbolToolProvider` creates `ImportExportToolProvider` helper instance
- `handleImportsMode()` delegates to `importExportHelper.collectImports()`
- `handleExportsMode()` delegates to `importExportHelper.collectExports()`
- `handleImportsMode()` delegates to `importExportHelper.paginate()` and `importExportHelper.groupImportsByLibrary()`

### 2. ImportExportToolProvider → CrossReferencesToolProvider

**Extracted Method:**
- `buildThunkChain(Function)` - Used by CrossReferencesToolProvider.handleThunkMode()

**Active Tool Integration:**
- `CrossReferencesToolProvider` creates `ImportExportToolProvider` helper instance
- `handleThunkMode()` delegates to `importExportHelper.buildThunkChain()`
- Removed duplicate `buildThunkChain()` method from CrossReferencesToolProvider

### 3. ProjectToolProvider

**Disabled Tools:**
- `registerOpenProjectTool()` → Merged into `open` (detects .gpr files)
- `registerOpenProgramTool()` → Merged into `open` (detects program files)
- `registerOpenAllProgramsInCodeBrowserTool()` → Merged into `open` (with extensions parameter)

**Extracted Methods (protected):**
- `handleOpenProject(Map, String, ToolLogCollector)` - Used by active `open` tool and disabled `registerOpenProjectTool()`
- `handleOpenProgram(Map, String)` - Used by active `open` tool and disabled `registerOpenProgramTool()`
- `handleOpenAllProgramsByExtension(String, String)` - Used by active `open` tool and disabled `registerOpenAllProgramsInCodeBrowserTool()`

**Active Tool Integration:**
- Active `open` tool calls:
  - `handleOpenProject()` for .gpr files
  - `handleOpenProgram()` for program files
  - `handleOpenAllProgramsByExtension()` when extensions parameter is provided
- Disabled tools call the same handler methods

### 4. DataToolProvider

**Disabled Tools:**
- `registerGetDataTool()` → Disabled (functionality may be available elsewhere)
- `registerApplyDataTypeTool()` → Disabled (functionality may be available elsewhere)
- `registerCreateLabelTool()` → Disabled (functionality may be available elsewhere)

**Extracted Methods (protected):**
- `getDataAtAddressResult(Program, Address)` - Extracted from registerGetDataTool()
- `applyDataTypeAtAddress(Program, Address, String, String)` - Extracted from registerApplyDataTypeTool()
- `createLabelAtAddress(Program, Address, String, boolean)` - Extracted from registerCreateLabelTool()

**Status:**
- Methods are extracted and protected for future use
- Not currently used by active tools, but available if needed

## Verification Checklist

- [x] All disabled tool handlers call extracted handler methods
- [x] All extracted handler methods are protected
- [x] Active tools delegate to disabled tool provider methods where applicable
- [x] Duplicate logic removed from active tools
- [x] Documentation added noting upstream sync requirements
- [x] Helper instances created where needed (SymbolToolProvider, CrossReferencesToolProvider)

## Upstream Sync Process

When upstream updates disabled tool handlers:

1. **Identify the change**: Check what was updated in the disabled tool handler
2. **Update extracted method**: Modify the corresponding protected handler/helper method
3. **Test active tools**: Verify that active tools using the method still work correctly
4. **Update documentation**: Note the change in this document if significant

## Files Modified

- `src/main/java/reva/tools/imports/ImportExportToolProvider.java`
  - Made helper methods protected
  - Extracted handler methods: `handleFindImportReferences()`, `handleResolveThunk()`
  - Updated disabled tool handlers to call extracted methods

- `src/main/java/reva/tools/symbols/SymbolToolProvider.java`
  - Added `ImportExportToolProvider` helper instance
  - Removed duplicate `collectImports()` and `collectExports()` methods
  - Removed duplicate `paginate()` and `groupImportsByLibrary()` methods
  - Updated to delegate to `importExportHelper` methods

- `src/main/java/reva/tools/xrefs/CrossReferencesToolProvider.java`
  - Added `ImportExportToolProvider` helper instance
  - Removed duplicate `buildThunkChain()` method
  - Updated to delegate to `importExportHelper.buildThunkChain()`

- `src/main/java/reva/tools/project/ProjectToolProvider.java`
  - Made `handleOpenProject()` and `handleOpenProgram()` protected
  - Made `handleOpenAllProgramsByExtension()` protected
  - Added documentation noting upstream sync requirements

- `src/main/java/reva/tools/data/DataToolProvider.java`
  - Uncommented and made helper methods protected
  - Added documentation for future use

## Benefits

1. **Upstream Updates**: When upstream improves disabled tool handlers, we can update the extracted methods and all active tools benefit automatically
2. **No Duplication**: Active tools don't duplicate logic - they delegate to the source
3. **Maintainability**: Single source of truth for shared logic
4. **Future-Proof**: Helper methods are available if needed later

## Notes

- Helper instances are created in constructors to access protected methods
- All extracted methods are documented with notes about upstream compatibility
- Linter warnings about unused methods are expected (disabled tool registration methods)
