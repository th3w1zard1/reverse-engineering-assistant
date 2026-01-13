# Ghidra Scripts Analysis and Coverage

This document analyzes all Ghidra scripts to ensure ReVa tools provide complete coverage.

## Script Categories

### 1. Program Import/Export
- `ImportProgramScript.java` - Import program ✅ (covered by `open` tool)
- `ImportAllProgramsFromADirectoryScript.java` - Batch import ✅ (covered by `manage-files` operation='import')
- `ExportProgramScript.java` - Export program ✅ (covered by `manage-files` operation='export' export_type='program')
- `ExportFunctionInfoScript.java` - Export function info ✅ (covered by `manage-files` operation='export' export_type='function_info')
- `ExportImagesScript.java` - Export images ❌ **MISSING** (low priority - specialized)
- `CreateExportFileForDLL.java` - Create export file ❌ **MISSING** (low priority - specialized)

### 2. Function Management
- `CreateFunctionAfterTerminals.java` - Create functions ✅ (covered by `manage-function` action='create')
- `CreateFunctionsFromSelection.java` - Create from selection ❌ **MISSING** (could add to manage-function)
- `MakeFunctionsScript.java` - Make functions ✅ (covered by `manage-function` action='create')
- `MakeFunctionsInlineVoidScript.java` - Make inline void ❌ **MISSING**
- `ClearOrphanFunctions.java` - Clear orphan functions ❌ **MISSING**
- `FindUndefinedFunctionsScript.java` - Find undefined ✅ (covered by `list-functions` mode='undefined')
- `FindUndefinedFunctionsFollowUpScript.java` - Follow-up undefined ❌ **MISSING**
- `FindSharedReturnFunctionsScript.java` - Find shared returns ❌ **MISSING**
- `FindInstructionsNotInsideFunctionScript.java` - Find orphan instructions ❌ **MISSING**

### 3. Symbol/Label Management
- `AutoRenameLabelsScript.java` - Auto rename labels ✅ (covered by `manage-symbols` mode='auto_rename')
- `AutoRenameSimpleLabels.java` - Auto rename simple ✅ (covered by `manage-symbols` mode='auto_rename')
- `BatchRename.java` - Batch rename ✅ (covered by `manage-symbols` mode='batch_rename')
- `DemangleAllScript.java` - Demangle all symbols ✅ (covered by `manage-symbols` mode='demangle' demangle_all=true)
- `DemangleSymbolScript.java` - Demangle single symbol ✅ (covered by `manage-symbols` mode='demangle')
- `ConvertDotToDashInAutoAnalysisLabels.java` - Convert labels ❌ **MISSING** (low priority - formatting)
- `RemoveSymbolQuotesScript.java` - Remove quotes ❌ **MISSING** (low priority - formatting)
- `RenameStructMembers.java` - Rename struct members ❌ **MISSING** (could add to manage-structures)

### 4. Comment Management
- `AddCommentToProgramScript.java` - Add comment ✅ (covered by `manage-comments` action='set')
- `FindAndReplaceCommentScript.java` - Find/replace comments ❌ **MISSING** (could add to manage-comments)
- `ReplaceInComments.java` - Replace in comments ❌ **MISSING**
- `DeleteDeadDefaultPlatesScript.java` - Delete dead plates ❌ **MISSING**
- `DeleteEmptyPlateCommentsScript.java` - Delete empty plates ❌ **MISSING**
- `DeleteExitCommentsScript.java` - Delete exit comments ❌ **MISSING**
- `DeleteFunctionDefaultPlatesScript.java` - Delete function plates ❌ **MISSING**

### 5. Data Type Management
- `ChooseDataTypeScript.java` - Choose data type ✅ (covered by `manage-data-types` action='apply')
- `FindDataTypeScript.java` - Find data type ✅ (covered by `manage-data-types` action='by_string')
- `FindDataTypeConflictCauseScript.java` - Find conflicts ❌ **MISSING**
- `FixupCompositeDataTypesScript.java` - Fixup composites ❌ **MISSING**
- `FixupGolangFuncParamStorageScript.java` - Fixup Golang ❌ **MISSING**
- `FixupNoReturnFunctionsScript.java` - Fixup no-return ❌ **MISSING**
- `FixupNoReturnFunctionsNoRepairScript.java` - Fixup no-return (no repair) ❌ **MISSING**
- `RenameVariable.java` - Rename variable ✅ (covered by `manage-function` action='rename_variable')
- `FixOldSTVariableStorageScript.java` - Fix old storage ❌ **MISSING**

### 6. Structure Management
- `PrintStructureScript.java` - Print structure ✅ (covered by `manage-structures` action='info')
- `RenameStructMembers.java` - Rename members ❌ **MISSING** (could add to manage-structures)

### 7. Memory/Data Operations
- `EditBytesScript.java` - Edit bytes ❌ **MISSING** (could add to inspect-memory)
- `ReadMemoryScript.java` - Read memory ✅ (covered by `inspect-memory` mode='read')
- `LabelDataScript.java` - Label data ✅ (covered by `manage-symbols` mode='create_label')
- `CreateStringScript.java` - Create string ❌ **MISSING** (could add to manage-strings)
- `IterateDataScript.java` - Iterate data ✅ (covered by `inspect-memory` mode='data_items')
- `CondenseRepeatingBytes.java` - Condense bytes ❌ **MISSING**
- `CondenseAllRepeatingBytes.java` - Condense all ❌ **MISSING**
- `CondenseFillerBytes.java` - Condense filler ❌ **MISSING**
- `CondenseRepeatingBytesAtEndOfMemory.java` - Condense end ❌ **MISSING**
- `XorMemoryScript.java` - XOR memory ❌ **MISSING**

### 8. String Operations
- `CountAndSaveStrings.java` - Count strings ✅ (covered by `manage-strings` mode='count')
- `SearchMemoryForStringsRegExScript.java` - Search strings ✅ (covered by `manage-strings` mode='regex')
- `NameStringPointersPlus.java` - Name string pointers ❌ **MISSING**
- `LabelIndirectStringReferencesScript.java` - Label string refs ❌ **MISSING**
- `BinaryToAsciiScript.java` - Binary to ASCII ❌ **MISSING**
- `AsciiToBinaryScript.java` - ASCII to binary ❌ **MISSING**

### 9. Reference Management
- `CreateOperandReferencesInSelectionScript.java` - Create refs ❌ **MISSING** (could add to get-references)
- `CreateRelocationBasedOperandReferences.java` - Create relocation refs ❌ **MISSING**
- `LabelDirectFunctionReferencesScript.java` - Label direct refs ❌ **MISSING**
- `LabelIndirectReferencesScript.java` - Label indirect refs ❌ **MISSING**
- `PropagateConstantReferences.java` - Propagate constants ❌ **MISSING**
- `PropagateX86ConstantReferences.java` - Propagate x86 constants ❌ **MISSING**
- `PropagateExternalParametersScript.java` - Propagate externals ❌ **MISSING**
- `ResolveExternalReferences.java` - Resolve externals ❌ **MISSING**
- `RemoveDeletedOverlayReferences.java` - Remove overlay refs ❌ **MISSING**

### 10. Analysis Operations
- `GetAndSetAnalysisOptionsScript.java` - Analysis options ❌ **MISSING**
- `CompareAnalysisScript.java` - Compare analysis ❌ **MISSING**
- `TurnOffStackAnalysis.java` - Turn off stack ❌ **MISSING**
- `ReportDisassemblyErrors.java` - Report errors ❌ **MISSING**
- `ReportPercentDisassembled.java` - Report percent ❌ **MISSING**

### 11. Search Operations
- `FindTextScript.java` - Find text ❌ **MISSING** (could add to manage-strings or new search tool)
- `InstructionSearchScript.java` - Search instructions ❌ **MISSING**
- `SearchMnemonicsOpsConstScript.java` - Search mnemonics ❌ **MISSING**
- `SearchMnemonicsOpsNoConstScript.java` - Search mnemonics (no const) ❌ **MISSING**
- `SearchMnemonicsNoOpsNoConstScript.java` - Search mnemonics (no ops) ❌ **MISSING**
- `SearchBaseExtended.java` - Search base extended ❌ **MISSING**
- `SearchForImageBaseOffsets.java` - Search image base ❌ **MISSING**
- `SearchForImageBaseOffsetsScript.java` - Search image base (alt) ❌ **MISSING**
- `FindRunsOfPointersScript.java` - Find pointer runs ❌ **MISSING**
- `FindOverlappingCodeUnitsScript.java` - Find overlapping ❌ **MISSING**
- `FindAudioInProgramScript.java` - Find audio ❌ **MISSING**
- `FindImagesScript.java` - Find images ❌ **MISSING**

### 12. Disassembly Operations
- `RepairDisassemblyScript.java` - Repair disassembly ❌ **MISSING**
- `FixOffcutInstructionScript.java` - Fix offcut ❌ **MISSING**
- `DoARMDisassemble.java` - ARM disassemble ❌ **MISSING**
- `DoThumbDisassemble.java` - Thumb disassemble ❌ **MISSING**
- `AssembleScript.java` - Assemble ❌ **MISSING**
- `AssembleBlockScript.java` - Assemble block ❌ **MISSING**
- `AssembleCheckDevScript.java` - Assemble check ❌ **MISSING**

### 13. Binary Format Specific
- `PE_script.java` - PE operations ❌ **MISSING**
- `PEF_script.java` - PEF operations ❌ **MISSING**
- `COFF_Script.java` - COFF operations ❌ **MISSING**
- `COFF_ArchiveScript.java` - COFF archive ❌ **MISSING**
- `MachO_Script.java` - Mach-O operations ❌ **MISSING**
- `AppleSingleDoubleScript.java` - Apple formats ❌ **MISSING**
- `SplitUniversalBinariesScript.java` - Split universal ❌ **MISSING**
- `SplitMultiplePefContainersScript.java` - Split PEF ❌ **MISSING**
- `PortableExecutableRichPrintScript.java` - PE rich header ❌ **MISSING**
- `FindFunctionsUsingTOCinPEFScript.java` - Find TOC functions ❌ **MISSING**

### 14. ELF Specific
- `ExtractELFDebugFilesScript.java` - Extract debug files ❌ **MISSING**

### 15. DWARF Debug Info
- `DWARFLineInfoCommentScript.java` - DWARF line comments ❌ **MISSING**
- `DWARFLineInfoSourceMapScript.java` - DWARF source map ❌ **MISSING**
- `DWARFMacroScript.java` - DWARF macros ❌ **MISSING**
- `DWARFSetExternalDebugFilesLocationPrescript.java` - DWARF debug location ❌ **MISSING**

### 16. Source Mapping
- `AddSourceFileScript.java` - Add source file ❌ **MISSING**
- `AddSourceMapEntryScript.java` - Add source map ❌ **MISSING**
- `RemoveSourceMapEntryScript.java` - Remove source map ❌ **MISSING**
- `ShowSourceMapEntryStartsScript.java` - Show source map ❌ **MISSING**
- `SelectAddressesMappedToSourceFileScript.java` - Select mapped addresses ❌ **MISSING**
- `OpenSourceFileAtLineInEclipseScript.java` - Open in Eclipse ❌ **MISSING** (external tool)
- `OpenSourceFileAtLineInVSCodeScript.java` - Open in VSCode ❌ **MISSING** (external tool)

### 17. Version Control
- `VersionControl_AddAll.java` - VC add all ✅ (covered by `import-file` with enableVersionControl)
- `VersionControl_ResetAll.java` - VC reset all ❌ **MISSING**
- `VersionControl_UndoAllCheckout.java` - VC undo checkout ❌ **MISSING**
- `VersionControl_VersionSummary.java` - VC summary ❌ **MISSING**
- `RemoveUserCheckoutsScript.java` - Remove checkouts ❌ **MISSING**

### 18. Project Management
- `RenameProgramsInProjectScript.java` - Rename programs ❌ **MISSING**
- `CreateEmptyProgramScript.java` - Create empty program ❌ **MISSING**
- `GenerateLotsOfProgramsScript.java` - Generate programs ❌ **MISSING** (test utility)

### 19. Processor/Language Operations
- `ChangeProcessorScript.java` - Change processor ✅ (covered by `change-processor` tool)
- `ReloadSleighLanguage.java` - Reload Sleigh ❌ **MISSING**
- `Fix_ARM_Call_JumpsScript.java` - Fix ARM calls ❌ **MISSING**
- `Override_ARM_Call_JumpsScript.java` - Override ARM calls ❌ **MISSING**
- `Mips_Fix_T9_PositionIndependentCode.java` - Fix MIPS T9 ❌ **MISSING**

### 20. Equate Operations
- `SetEquateScript.java` - Set equate ❌ **MISSING**
- `ShowEquatesInSelectionScript.java` - Show equates ❌ **MISSING**

### 21. Switch Table Operations
- `AddReferencesInSwitchTable.java` - Add switch refs ❌ **MISSING**
- `AddSingleReferenceInSwitchTable.java` - Add single switch ref ❌ **MISSING**
- `FindUnrecoveredSwitchesScript.java` - Find unrecovered switches ❌ **MISSING**

### 22. Stack Operations
- `MakeStackRefs.java` - Make stack refs ❌ **MISSING**

### 23. Pcode Operations
- `MarkCallOtherPcode.java` - Mark call other ❌ **MISSING**
- `MarkUnimplementedPcode.java` - Mark unimplemented ❌ **MISSING**

### 24. Function Analysis
- `ComputeCyclomaticComplexity.java` - Compute complexity ❌ **MISSING**
- `PrintFunctionCallTreesScript.java` - Print call trees ✅ (covered by `get-call-graph` mode='tree')
- `IterateFunctionsScript.java` - Iterate functions ✅ (covered by `list-functions`)
- `IterateFunctionsByAddressScript.java` - Iterate by address ✅ (covered by `list-functions`)
- `SelectFunctionsScript.java` - Select functions ❌ **MISSING** (UI operation)
- `IterateInstructionsScript.java` - Iterate instructions ❌ **MISSING** (could add to get-function view='disassemble')

### 25. Data Flow / References
- `MultiInstructionMemReference.java` - Multi instruction refs ❌ **MISSING**

### 26. External Library Operations
- `AssociateExternalPELibrariesScript.java` - Associate PE libs ❌ **MISSING**

### 27. System Map Import
- `LinuxSystemMapImportScript.java` - Import system map ❌ **MISSING**

### 28. PDB Operations
- `CreatePdbXmlFilesScript.java` - Create PDB XML ❌ **MISSING**

### 29. GDT Operations
- `CreateDefaultGDTArchivesScript.java` - Create GDT archives ❌ **MISSING**
- `CreateExampleGDTArchiveScript.java` - Create example GDT ❌ **MISSING**
- `CreateUEFIGDTArchivesScript.java` - Create UEFI GDT ❌ **MISSING**
- `CompareGDTs.java` - Compare GDTs ❌ **MISSING**
- `SynchronizeGDTCategoryPaths.java` - Sync GDT paths ❌ **MISSING**

### 30. Repository Operations
- `RepositoryFileUpgradeScript.java` - Upgrade repository ❌ **MISSING**

### 31. Memory Block Operations
- `LocateMemoryAddressesForFileOffset.java` - Locate addresses ❌ **MISSING**
- `LocateMemoryAddressesForFileOffset.py` - Locate addresses (Python) ❌ **MISSING**

### 32. Architecture-Specific Fixes
- `FixArrayStructReferencesScript.java` - Fix array/struct refs ❌ **MISSING**
- `FixElfExternalOffsetDataRelocationScript.java` - Fix ELF relocations ❌ **MISSING**
- `FixupCompositeDataTypesScript.java` - Fixup composites ❌ **MISSING**

### 33. Utility Scripts
- `HelloWorldScript.java` - Hello world ❌ **MISSING** (example script)
- `HelloWorldPopupScript.java` - Hello popup ❌ **MISSING** (example script)
- `CallAnotherScript.java` - Call script ❌ **MISSING** (script execution)
- `CallAnotherScriptForAllPrograms.java` - Call for all ❌ **MISSING** (script execution)
- `CallotherCensusScript.java` - Call other census ❌ **MISSING**
- `FormatExampleScript.java` - Format example ❌ **MISSING** (example)
- `ProgressExampleScript.java` - Progress example ❌ **MISSING** (example)
- `ExampleColorScript.java` - Color example ❌ **MISSING** (UI example)
- `ExampleGraphServiceScript.java` - Graph example ❌ **MISSING** (UI example)
- `InnerClassScript.java` - Inner class example ❌ **MISSING** (example)
- `LanguagesAPIDemoScript.java` - Languages API demo ❌ **MISSING** (example)
- `BuildGhidraJarScript.java` - Build jar ❌ **MISSING** (build utility)
- `CreateHelpTemplateScript.java` - Create help template ❌ **MISSING** (utility)

### 34. YARA Integration
- `RunYARAFromGhidra.py` - Run YARA ❌ **MISSING**
- `YaraGhidraGUIScript.java` - YARA GUI ❌ **MISSING**

### 35. Embedded Finder
- `EmbeddedFinderScript.java` - Find embedded files ❌ **MISSING**

### 36. Miscellaneous
- `FFsBeGoneScript.java` - Remove FFs ❌ **MISSING**
- `DeleteSpacePropertyScript.java` - Delete space property ❌ **MISSING**
- `SetHeadlessContinuationOptionScript.java` - Set headless option ❌ **MISSING**
- `ZapBCTRScript.java` - Zap BCTR ❌ **MISSING**
- `RegisterTouchesPerFunction.java` - Register touches ❌ **MISSING**
- `GenerateMaskedBitStringScript.java` - Generate bit string ❌ **MISSING**
- `GraphClassesScript.java` - Graph classes ❌ **MISSING**
- `SubsToFuncsScript.java` - Subs to funcs ❌ **MISSING**
- `BatchSegregate64bit.java` - Segregate 64-bit ❌ **MISSING**
- `FindX86RelativeCallsScript.java` - Find x86 relative calls ❌ **MISSING**
- `ResolveX86orX64LinuxSyscallsScript.java` - Resolve syscalls ❌ **MISSING**
- `RepairFuncDefinitionUsageScript.java` - Repair func def ❌ **MISSING**
- `ConvertDotDotDotScript.java` - Convert dots ❌ **MISSING**
- `PasteCopiedListingBytesScript.java` - Paste bytes ❌ **MISSING**
- `SearchGuiMulti.java` - Search GUI multi ❌ **MISSING** (UI)
- `SearchGuiSingle.java` - Search GUI single ❌ **MISSING** (UI)
- `AskScript.java` - Ask script ❌ **MISSING** (UI)
- `AskValuesExampleScript.java` - Ask values ❌ **MISSING** (UI example)
- `EmbeddedFinderScript.java` - Embedded finder ❌ **MISSING**
- `MarkupWallaceSrcScript.java` - Wallace markup ❌ **MISSING**

### 37. Emulation
- `EmuX86DeobfuscateExampleScript.java` - X86 emulation ❌ **MISSING**
- `EmuX86GccDeobfuscateHookExampleScript.java` - X86 GCC emulation ❌ **MISSING**

### 38. Python Scripts
- `mark_in_out.py` - Mark in/out ❌ **MISSING**
- `RecursiveStringFinder.py` - Recursive string finder ❌ **MISSING**

## Priority Gaps to Address

### High Priority (Common Operations)
1. **Export functionality** - Export programs, function info, images
2. **Batch symbol rename** - Batch rename labels/symbols
3. **Find/replace in comments** - Search and replace comment text
4. **Instruction search** - Search for specific instructions/patterns
5. **Memory editing** - Edit bytes in memory
6. **Reference creation** - Create operand references
7. **Equate management** - Set/show equates
8. **Switch table operations** - Add references, find unrecovered switches

### Medium Priority (Useful Features)
1. **Demangle symbols** - Demangle C++/Rust symbols
2. **Auto-rename labels** - Automatic label renaming
3. **Data type conflict detection** - Find and fix conflicts
4. **Source mapping** - Add/remove source file mappings
5. **Analysis options** - Get/set analysis options
6. **Disassembly repair** - Repair disassembly errors

### Low Priority (Specialized/Niche)
1. **Format-specific operations** - PE/ELF/Mach-O specific features
2. **Architecture-specific fixes** - ARM/MIPS specific operations
3. **DWARF operations** - Debug info management
4. **Version control operations** - Advanced VC features
5. **Emulation** - Code emulation features

## Implementation Strategy

1. **Add to existing tools** where functionality fits naturally
2. **Create new unified tools** for major feature categories (e.g., `manage-references`, `search-code`)
3. **Keep intuitive naming** - tools should be guessable by AI agents
4. **Use mode/action enums** - consistent with existing tool patterns
