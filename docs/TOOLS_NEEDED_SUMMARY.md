# Tools Needed Summary

Based on analysis of upstream and the Ghidra Scripts Analysis document, here's what we need to add (disabled) to minimize merge conflicts.

## ✅ COMPLETED: Upstream Tool Alignment

### ImportExportToolProvider Registration
- **Status:** ✅ **COMPLETED**
- **Action:** Added `ImportExportToolProvider` to `McpServerManager.initializeToolProviders()`
- **Result:** Provider is registered but all tools remain disabled (commented out)
- **Impact:** Reduces merge conflicts in `McpServerManager.java`

### Disabled Tools Already Present
- ✅ `open-project` in `ProjectToolProvider` (disabled, merged into `open`)
- ✅ `open-program` in `ProjectToolProvider` (disabled, merged into `open`)
- ✅ `list-imports` in `ImportExportToolProvider` (disabled)
- ✅ `list-exports` in `ImportExportToolProvider` (disabled)
- ✅ `find-import-references` in `ImportExportToolProvider` (disabled)
- ✅ `resolve-thunk` in `ImportExportToolProvider` (disabled)

## 📋 Tools from Ghidra Scripts Analysis

The `GHIDRA_SCRIPTS_ANALYSIS.md` document lists many Ghidra scripts that could be converted to MCP tools. However, these are **NOT** currently in upstream, so we don't need to add them disabled yet.

### High Priority Gaps (for future implementation, not for upstream alignment)
These are tools we could add in the future, but they're not in upstream:

1. **Export functionality** - Export programs, function info, images
   - Status: We have `export` tool in `ProjectToolProvider` ✅
   - Action: None needed for upstream alignment

2. **Batch symbol rename** - Batch rename labels/symbols
   - Status: Not in upstream
   - Action: Could add to `SymbolToolProvider` if needed

3. **Find/replace in comments** - Search and replace comment text
   - Status: Not in upstream
   - Action: Could add to `CommentToolProvider` if needed

4. **Instruction search** - Search for specific instructions/patterns
   - Status: Not in upstream
   - Action: Could create new `SearchToolProvider` if needed

5. **Memory editing** - Edit bytes in memory
   - Status: Not in upstream
   - Action: Could add to `MemoryToolProvider` if needed

6. **Reference creation** - Create operand references
   - Status: Not in upstream
   - Action: Could add to `CrossReferencesToolProvider` if needed

7. **Equate management** - Set/show equates
   - Status: Not in upstream
   - Action: Could add to `SymbolToolProvider` or new tool if needed

8. **Switch table operations** - Add references, find unrecovered switches
   - Status: Not in upstream
   - Action: Could add to `FunctionToolProvider` if needed

## 🎯 Current Status: All Upstream Tools Aligned

**Summary:**
- ✅ All upstream tool providers are registered
- ✅ All upstream tools that we've consolidated are present but disabled
- ✅ Our custom additions (`GetFunctionToolProvider`, `SuggestionToolProvider`) remain active
- ✅ No additional tools needed for upstream alignment

## 📝 Notes

1. **Upstream Tools:** We've successfully aligned with all upstream tools by:
   - Registering `ImportExportToolProvider` (tools disabled)
   - Keeping disabled `open-project` and `open-program` methods
   - Maintaining our unified `open` tool

2. **Ghidra Scripts:** The scripts in `GHIDRA_SCRIPTS_ANALYSIS.md` are potential future enhancements, not upstream requirements. We should implement these as needed, not for upstream alignment.

3. **Merge Strategy:** By having all upstream tool providers registered (even with disabled tools), merge conflicts will be minimized because:
   - Tool provider registration order matches upstream
   - Disabled tools are present for reference
   - Our customizations are clearly marked

## ✅ Verification

All upstream alignment tasks are complete:
- [x] `ImportExportToolProvider` registered in `McpServerManager`
- [x] All disabled tool methods present in providers
- [x] Our custom providers remain active
- [x] File structure matches upstream expectations

**Result:** Diffs from upstream should now be much smaller! 🎉
