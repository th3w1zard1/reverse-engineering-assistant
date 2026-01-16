# ReVA Tools Reference

**30+ tools** that provide comprehensive reverse engineering capabilities through intelligent parameterization. This design reduces LLM context overhead, improves tool selection reliability, and maintains 100% feature coverage. Each tool uses enums, optional parameters, and defaults to provide flexible, powerful functionality.

## GUI Mode Support

**Important:** In GUI mode, the `programPath` parameter is **optional** for most tools. When `programPath` is not provided, ReVa automatically uses the currently active program in the Ghidra Code Browser. This makes interactive analysis more convenient - you can simply call tools without specifying which program to use, and ReVa will operate on the program you're currently viewing.

**GUI-specific tools:**
- `get-current-program` - Get information about the currently active program
- `get-current-address` - Get the address currently selected in the Code Browser
- `get-current-function` - Get the function currently selected in the Code Browser
- `list-open-programs` - List all programs currently open in Ghidra across all tools
- `open-program-in-code-browser` - Open a program in Ghidra's Code Browser tool

**Note:** In headless mode (when running without a GUI), `programPath` is still required for tools that operate on programs.

## Tool List

### 1. `manage-symbols`

**Description:** List classes, namespaces, imports, exports, create labels, get symbols, count symbols, or rename data labels.

**Modes:** `classes`, `namespaces`, `imports`, `exports`, `create_label`, `symbols`, `count`, `rename_data`, `demangle`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, required): Operation mode enum
- `address` (string or array, optional): Address(es) for create_label or rename_data modes
- `labelName` (string or array, optional): Label name(s) for create_label mode
- `newName` (string or array, optional): New name(s) for rename_data mode
- `libraryFilter` (string, optional): Filter to specific library for imports/exports modes
- `maxResults` (integer, optional): Maximum results to return (default: 500)
- `startIndex` (integer, optional): Starting index for pagination (default: 0)
- `offset` (integer, optional): Alternative pagination offset (default: 0)
- `limit` (integer, optional): Alternative pagination limit (default: 100)
- `groupByLibrary` (boolean, optional): Group imports/exports by library (default: true)
- `includeExternal` (boolean, optional): Include external symbols (default: false)
- `maxCount` (integer, optional): Maximum symbols to return (default: 200)
- `filterDefaultNames` (boolean, optional): Filter out default Ghidra names (default: true)
- `demangleAll` (boolean, optional): Demangle all symbols when mode='demangle' (default: false)

### 2. `manage-strings`

**Description:** List, search, count, or find similar strings in the program.

**Modes:** `list`, `regex`, `count`, `similarity`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, optional): Operation mode enum (default: 'list')
- `pattern` (string, optional): Regular expression pattern when mode='regex' (required for regex mode)
- `searchString` (string, optional): String to compare against for similarity when mode='similarity' (required for similarity mode)
- `filter` (string, optional): Optional filter to match within string content when mode='list'
- `startIndex` (integer, optional): Starting index for pagination (0-based, default: 0)
- `maxCount` (integer, optional): Maximum number of strings to return (default: 100)
- `offset` (integer, optional): Alternative pagination offset (default: 0)
- `limit` (integer, optional): Alternative pagination limit (default: 2000)
- `maxResults` (integer, optional): Maximum number of results when mode='regex' (default: 100)
- `includeReferencingFunctions` (boolean, optional): Include list of functions that reference each string (default: false)

### 3. `list-functions`

**Description:** List, search, or count functions in the program with various filtering and search modes.

**Modes:** `all`, `search`, `similarity`, `undefined`, `count`, `by_identifiers`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, optional): Operation mode enum (default: 'all')
- `query` (string, optional): Substring to search for when mode='search' (required for search mode)
- `searchString` (string, optional): Function name to compare against for similarity when mode='similarity' (required for similarity mode)
- `minReferenceCount` (integer, optional): Minimum number of references required when mode='undefined' (default: 1)
- `identifiers` (string or array, optional): Function name(s) or address(es) when mode='by_identifiers' (required for by_identifiers mode)
- `startIndex` (integer, optional): Starting index for pagination (0-based, default: 0)
- `maxCount` (integer, optional): Maximum number of functions to return (default: 100)
- `offset` (integer, optional): Alternative pagination offset (default: 0)
- `limit` (integer, optional): Alternative pagination limit (default: 100)
- `filterDefaultNames` (boolean, optional): Filter out default Ghidra generated names (default: true)
- `filterByTag` (string, optional): Filter functions by tag when mode='all'
- `untagged` (boolean, optional): Show only untagged functions when mode='all' (default: false)
- `hasTags` (boolean, optional): Show only functions with tags when mode='all' (default: false)
- `verbose` (boolean, optional): Return full function details (default: false)

### 4. `manage-function`

**Description:** Create, rename, or modify functions and their variables.

**Actions:** `create`, `rename_function`, `rename_variable`, `set_prototype`, `set_variable_type`, `change_datatypes`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum
- `address` (string or array, optional): Address(es) where function(s) should be created when action='create' (required for create, supports batch)
- `functionIdentifier` (string or array, optional): Function name(s) or address(es) for rename/modify operations (required for rename_function, rename_variable, set_prototype, set_variable_type, change_datatypes, supports batch)
- `name` (string, optional): New function name when action='rename_function' or optional name when action='create'
- `functions` (array, optional): Array of function rename objects for batch renaming
- `oldName` (string, optional): Old variable name when action='rename_variable' (required for single variable rename)
- `newName` (string, optional): New variable name when action='rename_variable' (required for single variable rename)
- `variableMappings` (string, optional): Mapping of old to new variable names when action='rename_variable' (format: "oldName1:newName1,oldName2:newName2")
- `prototype` (string or array, optional): Function prototype/signature string(s) when action='set_prototype' (required for set_prototype, supports batch)
- `variableName` (string, optional): Variable name when action='set_variable_type' (required for set_variable_type)
- `newType` (string, optional): New data type for variable when action='set_variable_type' (required for set_variable_type)
- `datatypeMappings` (string, optional): Mapping of variable names to new data type strings when action='change_datatypes' (format: "varName1:type1,varName2:type2")
- `archiveName` (string, optional): Optional name of the data type archive to search for data types when action='change_datatypes' (default: "")
- `createIfNotExists` (boolean, optional): Create function if it doesn't exist when action='set_prototype' (default: true)
- `propagate` (boolean, optional): When true, attempts to find the matching function in other open programs (via fingerprint) and apply the same change there automatically (default: true)
- `propagateProgramPaths` (array, optional): Optional list of programPath values to propagate changes to
- `propagateMaxCandidates` (integer, optional): When ambiguous, include up to this many candidates in the response per target program (default: 10)
- `propagateMaxInstructions` (integer, optional): Number of instructions used for fingerprinting when propagating (default: 64)

### 5. `manage-function-tags`

**Description:** Manage function tags. Tags categorize functions (e.g., 'AI', 'rendering'). Use mode='list' for all tags in program.

**Modes:** `get`, `set`, `add`, `remove`, `list`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `function` (string or array, optional): Function name or address (required for get/set/add/remove modes, not required for list mode, supports batch)
- `mode` (string, required): Operation mode enum
- `tags` (array, optional): Tag names (required for add; optional for set/remove). Empty/whitespace names are ignored.

### 6. `match-function`

**Description:** Match functions across programs using code fingerprints and transfer function names, tags, and comments from a source program to matching functions in target programs. Supports both single-function matching and batch transfer of labeled functions across similar binaries (e.g., swkotor.exe -> swkotor2.exe).

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the source program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `functionIdentifier` (string, optional): Function name or address to match. If provided, only matches and transfers metadata for this specific function. If omitted, matches and transfers all functions from the source program.
- `targetProgramPaths` (array, optional): List of programPath values to search/transfer to. If omitted, searches/transfers to all open programs except source.
- `maxInstructions` (integer, optional): Number of instructions to fingerprint/compare (default: 64; higher improves uniqueness/accuracy but costs more).
- `minSimilarity` (number, optional): Minimum similarity score (0.0-1.0) required to match and transfer. 0.85 = 85% similar, 0.90 = 90% similar. Higher = more strict matching (default: 0.85)
- `propagateNames` (boolean, optional): Transfer function names (default: true)
- `propagateTags` (boolean, optional): Transfer function tags (default: true)
- `propagateComments` (boolean, optional): Transfer function comments (default: false)
- `filterDefaultNames` (boolean, optional): Only process functions that don't have default Ghidra names (FUN_*, etc.) in source (default: true)
- `filterByTag` (string, optional): Only process functions with this tag in source program
- `dryRun` (boolean, optional): Preview what would be transferred without making changes (default: false)
- `maxFunctions` (integer, optional): Maximum number of functions to process (for testing/debugging, 0 = unlimited, default: 0)
- `batchSize` (integer, optional): Number of functions to process per transaction (default: 100). Larger = faster but less granular progress.

### 8. `inspect-memory`

**Description:** Inspect memory blocks, read memory, get data information, list data items, or list memory segments.

**Modes:** `blocks`, `read`, `data_at`, `data_items`, `segments`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, required): Inspection mode enum
- `address` (string, optional): Address to read from when mode='read' or address to query when mode='data_at' (required for read/data_at modes)
- `length` (integer, optional): Number of bytes to read when mode='read' (default: 16)
- `offset` (integer, optional): Pagination offset when mode='data_items' or 'segments' (default: 0)
- `limit` (integer, optional): Maximum number of items to return when mode='data_items' or 'segments' (default: 100)

### 9. `open`

**Description:** Open a Ghidra project (.gpr file), a program file, or multiple programs by extension. For projects: opens the project and optionally loads all programs into memory. For single programs: imports if missing, opens if exists. Always saves to project. Caches for other tools. For bulk operations: provide 'extensions' parameter to open all matching programs in Code Browser.

**Parameters:**
- `path` (string, optional): Path to open: a Ghidra project file (.gpr), a program file, or a project folder path. If extensions is provided, this is treated as a folder path (default: '/'). If .gpr, opens the project. Otherwise, imports/opens the program in the active project.
- `extensions` (string, optional): Optional: comma-separated list of file extensions to open (e.g., 'exe,dll' or 'exe'). If provided, opens all matching programs in Code Browser instead of opening a single file. Defaults to 'exe,dll' when extensions is provided. Ignored if not provided.
- `openAllPrograms` (boolean, optional): For projects: whether to automatically open all programs into memory (default: true). Ignored for program files or when extensions is provided.
- `destinationFolder` (string, optional): For programs: project folder for new imports (default: '/'). Ignored for projects, bulk operations, or if program exists.
- `analyzeAfterImport` (boolean, optional): For programs: run auto-analysis on new imports (default: true). Ignored for projects, bulk operations, or if program exists.
- `enableVersionControl` (boolean, optional): For programs: add new imports to version control (default: true). Ignored for projects, bulk operations, or if program exists.
- `serverUsername` (string, optional): For shared projects: Username for Ghidra Server authentication. If not provided, will check REVA_SERVER_USERNAME environment variable.
- `serverPassword` (string, optional): For shared projects: Password for Ghidra Server authentication. If not provided, will check REVA_SERVER_PASSWORD environment variable.
- `serverHost` (string, optional): For shared projects: Ghidra Server hostname or IP address. If not provided, will check REVA_SERVER_HOST environment variable.
- `serverPort` (integer, optional): For shared projects: Ghidra Server port (default: 13100). If not provided, will check REVA_SERVER_PORT environment variable.
- `forceIgnoreLock` (boolean, optional): For projects: whether to forcibly ignore lock files by deleting them before opening (default: false, or REVA_FORCE_IGNORE_LOCK env var)

### 10. `list-project-files`

**Description:** List files and folders in the Ghidra project.

**Parameters:**
- `folderPath` (string, required): Path to the folder to list contents of. Use '/' for the root folder.
- `recursive` (boolean, optional): Whether to list files recursively (default: false)

### 11. `list-open-programs` (GUI Mode Only)

**Description:** List all programs currently open in Ghidra across all tools.

**Parameters:** None

### 12. `get-current-program` (GUI Mode Only)

**Description:** Get the currently active program in Ghidra.

**Parameters:** None

### 13. `get-current-address` (GUI Mode Only)

**Description:** Get the address currently selected by the user in the Code Browser.

**Parameters:** None

### 14. `get-current-function` (GUI Mode Only)

**Description:** Get the function currently selected by the user in the Code Browser.

**Parameters:** None

### 15. `open-program-in-code-browser` (GUI Mode Only)

**Description:** Open a program in Ghidra's Code Browser tool. The program will be opened if not already open.

**Parameters:**
- `programPath` (string, required): Path to the program to open in Code Browser (e.g., '/swkotor.exe')

### 16. `checkin-program`

**Description:** Checkin (commit) a program to version control with a commit message.

**Parameters:**
- `programPath` (string, required): Path to the program to checkin (e.g., '/Hatchery.exe')
- `message` (string, required): Commit message for the checkin
- `keepCheckedOut` (boolean, optional): Whether to keep the program checked out after checkin (default: false)

### 17. `analyze-program`

**Description:** Run Ghidra's auto-analysis on a program.

**Parameters:**
- `programPath` (string, required): Path to the program to analyze (e.g., '/Hatchery.exe')

### 18. `change-processor`

**Description:** Change the processor architecture of an existing program.

**Parameters:**
- `programPath` (string, required): Path to the program to modify (e.g., '/Hatchery.exe')
- `languageId` (string, required): Language ID for the new processor (e.g., 'x86:LE:64:default')
- `compilerSpecId` (string, optional): Compiler spec ID (optional, defaults to the language's default)

### 19. `manage-files`

**Description:** Import files into the Ghidra project or export program data to files.

**Parameters:**
- `operation` (string, required): Operation to perform: 'import' (import files into project) or 'export' (export program data to files)
- `path` (string, required): For import: Absolute file system path to import (file, directory, or archive). For export: File system path where to save the exported file. Use absolute paths to ensure proper file resolution.
- `destinationFolder` (string, optional): Project folder path for imported files (default: root folder '/')
- `recursive` (boolean, optional): Whether to recursively import from containers/archives (default: true)
- `maxDepth` (integer, optional): Maximum container depth to recurse into (default: 10)
- `analyzeAfterImport` (boolean, optional): Run auto-analysis after import (default: true)
- `stripLeadingPath` (boolean, optional): Omit the source file's leading path from imported file locations (default: true)
- `stripAllContainerPath` (boolean, optional): Completely flatten container paths in imported file locations (default: false)
- `mirrorFs` (boolean, optional): Mirror the filesystem layout when importing (default: false)
- `enableVersionControl` (boolean, optional): For import: Automatically add imported files to version control (default: true)
- `programPath` (string, optional): For export: Path to the program to export (e.g., '/Hatchery.exe')
- `exportType` (string, optional): For export: Type of export: 'program' (export binary), 'function_info' (export function information as JSON/CSV), 'strings' (export strings as text)
- `format` (string, optional): For export: Export format for function_info: 'json' or 'csv' (default: 'json')
- `includeParameters` (boolean, optional): For export: Include function parameters in function_info export (default: true)
- `includeVariables` (boolean, optional): For export: Include local variables in function_info export (default: true)
- `includeComments` (boolean, optional): For export: Include comments in function_info export (default: false)

### 20. `get-references`

**Description:** Find and analyze references to/from addresses, symbols, functions, or imports, with optional decompilation of referencers.

**Modes:** `to`, `from`, `both`, `function`, `referencers_decomp`, `import`, `thunk`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `target` (string, required): Target address, symbol name, function name, or import name
- `mode` (string, optional): Reference mode enum (default: 'both')
- `direction` (string, optional): Direction filter when mode='both' enum ('to', 'from', 'both'; default: 'both')
- `offset` (integer, optional): Pagination offset (default: 0)
- `limit` (integer, optional): Maximum number of references to return (default: 100)
- `maxResults` (integer, optional): Alternative limit parameter for import mode (default: 100)
- `libraryName` (string, optional): Optional specific library name to narrow search when mode='import' (case-insensitive)
- `startIndex` (integer, optional): Starting index for pagination when mode='referencers_decomp' (0-based, default: 0)
- `maxReferencers` (integer, optional): Maximum number of referencing functions to decompile when mode='referencers_decomp' (default: 10)
- `includeRefContext` (boolean, optional): Whether to include reference line numbers in decompilation when mode='referencers_decomp' (default: true)
- `includeDataRefs` (boolean, optional): Whether to include data references (reads/writes), not just calls when mode='referencers_decomp' (default: true)

### 21. `manage-data-types`

**Description:** Get data type archives, list data types, get data type by string representation, or apply data types to addresses/symbols.

**Actions:** `archives`, `list`, `by_string`, `apply`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum
- `archiveName` (string, optional): Name of the data type archive when action='list', 'by_string', or 'apply' (required for list, optional for by_string/apply)
- `categoryPath` (string, optional): Path to category to list data types from when action='list' (e.g., '/Structure', use '/' for root, default: '/')
- `includeSubcategories` (boolean, optional): Whether to include data types from subcategories when action='list' (default: false)
- `startIndex` (integer, optional): Starting index for pagination when action='list' (0-based, default: 0)
- `maxCount` (integer, optional): Maximum number of data types to return when action='list' (default: 100)
- `dataTypeString` (string, optional): String representation of the data type when action='by_string' or 'apply' (e.g., 'char**', 'int[10]', required for by_string/apply)
- `addressOrSymbol` (string, optional): Address or symbol name to apply the data type to when action='apply' (required for apply)

### 22. `manage-structures`

**Description:** Parse, validate, create, modify, query, list, apply, or delete structures. Also parse entire C header files.

**Actions:** `parse`, `validate`, `create`, `add_field`, `modify_field`, `modify_from_c`, `info`, `list`, `apply`, `delete`, `parse_header`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum
- `cDefinition` (string, optional): C-style structure definition when action='parse', 'validate', or 'modify_from_c' (required for parse/validate/modify_from_c)
- `headerContent` (string, optional): C header file content when action='parse_header' (required for parse_header)
- `structureName` (string, optional): Name of the structure (required for add_field, modify_field, info, apply, delete; optional for list)
- `name` (string, optional): Name of the structure when action='create' (required for create)
- `size` (integer, optional): Initial size when action='create' (0 for auto-sizing, default: 0)
- `type` (string, optional): Structure type when action='create' enum ('structure', 'union'; default: 'structure')
- `category` (string, optional): Category path (default: '/')
- `packed` (boolean, optional): Whether structure should be packed when action='create' (default: false)
- `description` (string, optional): Description of the structure when action='create'
- `fieldName` (string, optional): Name of the field when action='add_field' or 'modify_field' (required for add_field, optional for modify_field)
- `dataType` (string, optional): Data type when action='add_field' (e.g., 'int', 'char[32]', required for add_field)
- `offset` (integer, optional): Field offset when action='add_field' or 'modify_field' (optional, omit to append for add_field)
- `comment` (string, optional): Field comment when action='add_field'
- `newDataType` (string, optional): New data type for the field when action='modify_field'
- `newFieldName` (string, optional): New name for the field when action='modify_field'
- `newComment` (string, optional): New comment for the field when action='modify_field'
- `newLength` (integer, optional): New length for the field when action='modify_field' (advanced, optional)
- `addressOrSymbol` (string, optional): Address or symbol name to apply structure when action='apply' (required for apply)
- `clearExisting` (boolean, optional): Clear existing data when action='apply' (default: true)
- `force` (boolean, optional): Force deletion even if structure is referenced when action='delete' (default: false)
- `nameFilter` (string, optional): Filter by name (substring match) when action='list'
- `includeBuiltIn` (boolean, optional): Include built-in types when action='list' (default: false)

### 23. `manage-comments`

**Description:** Set, get, remove, or search comments in decompiled code, disassembly, or at addresses. Also search patterns across all decompilations.

**Actions:** `set`, `get`, `remove`, `search`, `search_decomp`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum
- `address` (string, optional): Address where to set/get/remove the comment (required for set/remove when not using function/line_number)
- `addressOrSymbol` (string, optional): Address or symbol name (alternative parameter, used for set/get/remove)
- `function` (string, optional): Function name or address when setting decompilation line comment or searching decompilation (required for set with line_number, optional for search_decomp)
- `functionNameOrAddress` (string, optional): Function name or address (alternative parameter name)
- `lineNumber` (integer, optional): Line number in the decompiled function when action='set' with decompilation (1-based, required for decompilation line comments)
- `comment` (string, optional): The comment text to set (required for set)
- `commentType` (string, optional): Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable'; default: 'eol')
- `comments` (array, optional): Array of comment objects for batch operations when action='set'
- `start` (string, optional): Start address of the range when action='get'
- `end` (string, optional): End address of the range when action='get'
- `commentTypes` (string, optional): Types of comments to retrieve/search (comma-separated: pre,eol,post,plate,repeatable)
- `searchText` (string, optional): Text to search for in comments when action='search' (required for search)
- `pattern` (string, optional): Regular expression pattern to search for when action='search_decomp' (required for search_decomp)
- `caseSensitive` (boolean, optional): Whether search is case sensitive when action='search' or 'search_decomp' (default: false)
- `maxResults` (integer, optional): Maximum number of results to return when action='search' or 'search_decomp' (default: 100 for search, 50 for search_decomp)
- `overrideMaxFunctionsLimit` (boolean, optional): Whether to override the maximum function limit for decompiler searches when action='search_decomp' (default: false)

### 24. `manage-bookmarks`

**Description:** Create, retrieve, search, remove bookmarks, or list bookmark categories.

**Actions:** `set`, `get`, `search`, `remove`, `remove_all`, `categories`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum
- `address` (string, optional): Address where to set/get/remove the bookmark (required for set/remove, optional for get)
- `addressOrSymbol` (string, optional): Address or symbol name (alternative parameter name, used for remove action)
- `type` (string, optional): Bookmark type enum ('Note', 'Warning', 'TODO', 'Bug', 'Analysis'; required for set/remove, optional for get/categories)
- `category` (string, optional): Bookmark category for organization (required for set, optional for remove)
- `comment` (string, optional): Bookmark comment text (required for set)
- `bookmarks` (array, optional): Array of bookmark objects for batch operations when action='set'
- `searchText` (string, optional): Text to search for in bookmark comments when action='search' (required for search)
- `maxResults` (integer, optional): Maximum number of results to return when action='search' (default: 100)
- `removeAll` (boolean, optional): Remove all bookmarks when action='remove_all' (default: false)

### 25. `analyze-data-flow`

**Description:** Trace data flow backward (origins), forward (uses), or find variable accesses within a function.

**Directions:** `backward`, `forward`, `variable_accesses`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `functionAddress` (string, required): Address of the function to analyze
- `startAddress` (string, optional): Address within the function to trace from when direction='backward' or 'forward' (required for backward/forward)
- `variableName` (string, optional): Name of the variable to find accesses for when direction='variable_accesses' (required for variable_accesses)
- `direction` (string, required): Analysis direction enum

### 26. `get-call-graph`

**Description:** Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees, caller/callee lists, decompiled callers, or common callers.

**Modes:** `graph`, `tree`, `callers`, `callees`, `callers_decomp`, `common_callers`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `functionIdentifier` (string, required): Function name or address
- `mode` (string, optional): Analysis mode enum (default: 'graph')
- `depth` (integer, optional): Depth of call graph to retrieve when mode='graph' (default: 1)
- `direction` (string, optional): Direction to traverse when mode='tree' or 'callers' or 'callees' enum ('callers', 'callees'; default: 'callees' for tree)
- `maxDepth` (integer, optional): Maximum depth to traverse when mode='tree' (default: 3, max: 10)
- `startIndex` (integer, optional): Starting index for pagination when mode='callers_decomp' (0-based, default: 0)
- `maxCallers` (integer, optional): Maximum number of calling functions to decompile when mode='callers_decomp' (default: 10)
- `includeCallContext` (boolean, optional): Whether to highlight the line containing the call in each decompilation when mode='callers_decomp' (default: true)
- `functionAddresses` (string, optional): Comma-separated list of function addresses or names when mode='common_callers' (required for common_callers mode)

### 27. `search-constants`

**Description:** Find specific constants, constants in ranges, or list the most common constants in the program.

**Modes:** `specific`, `range`, `common`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, required): Search mode enum
- `value` (string, optional): Constant value to search for when mode='specific' (supports hex with 0x, decimal, negative; required for specific mode)
- `minValue` (string, optional): Minimum value when mode='range' or filter minimum when mode='common' (inclusive, supports hex/decimal; required for range mode)
- `maxValue` (string, optional): Maximum value when mode='range' (inclusive, supports hex/decimal; required for range mode)
- `maxResults` (integer, optional): Maximum number of results to return when mode='specific' or 'range' (default: 500)
- `includeSmallValues` (boolean, optional): Include small values (0-255) which are often noise when mode='common' (default: false)
- `topN` (integer, optional): Number of most common constants to return when mode='common' (default: 50)

### 28. `analyze-vtables`

**Description:** Analyze vtables, find vtable callers, or find vtables containing a specific function.

**Modes:** `analyze`, `callers`, `containing`

**Parameters:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, required): Analysis mode enum
- `vtableAddress` (string, optional): Address of the vtable to analyze when mode='analyze' (required for analyze mode)
- `functionAddress` (string, optional): Address or name of the virtual function when mode='callers' or function to search for when mode='containing' (required for callers/containing modes)
- `maxEntries` (integer, optional): Maximum number of vtable entries to read when mode='analyze' (default: 200)
- `maxResults` (integer, optional): Maximum number of results to return when mode='callers' or 'containing' (default: 100)

### 29. `get-functions`

**Description:** Get function details in various formats: decompiled code, assembly, function information, or internal calls. Supports single function, batch operations when identifier is an array, or all functions when identifier is omitted.

**Views:** `decompile`, `disassemble`, `info`, `calls`

**Parameters:**
- `programPath` (string or array, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser. Can be an array for multi-program analysis.
- `identifier` (string or array, optional): Function name or address (e.g., 'main' or '0x401000'). Can be a single string or an array of strings for batch operations. When omitted, returns all functions.
- `view` (string, optional): View mode enum (default: 'decompile')
- `offset` (integer, optional): Line number to start reading from when view='decompile' (1-based, default: 1)
- `limit` (integer, optional): Number of lines to return when view='decompile' (default: 50)
- `includeCallers` (boolean, optional): Include list of functions that call this one when view='decompile' (default: false)
- `includeCallees` (boolean, optional): Include list of functions this one calls when view='decompile' (default: false)
- `includeComments` (boolean, optional): Whether to include comments in the decompilation when view='decompile' (default: false)
- `includeIncomingReferences` (boolean, optional): Whether to include incoming cross references when view='decompile' (default: true)
- `includeReferenceContext` (boolean, optional): Whether to include code context snippets from calling functions when view='decompile' (default: true)

### 30. `capture-reva-debug-info`

**Description:** Creates a zip file containing ReVa debug information for troubleshooting issues. Includes system info, Ghidra config, ReVa settings, MCP server status, open programs, and logs.

**Parameters:**
- `message` (string, optional): Optional message describing the issue being debugged

---

## 📊 Tool Consolidation Summary

The 30+ tools above provide comprehensive reverse engineering capabilities:

- **Symbol Management**: `manage-symbols`
- **String Analysis**: `manage-strings`
- **Function Analysis**: `list-functions`, `manage-function`, `manage-function-tags`, `match-function`, `get-functions`
- **Memory Inspection**: `inspect-memory`
- **Project Management**: `open`, `list-project-files`, `list-open-programs`, `get-current-program`, `get-current-address` (GUI), `get-current-function` (GUI), `open-program-in-code-browser` (GUI), `checkin-program`, `analyze-program`, `change-processor`, `manage-files`, `capture-reva-debug-info`
- **Cross-References**: `get-references`
- **Type Management**: `manage-data-types`
- **Structure Management**: `manage-structures`
- **Annotations**: `manage-comments`, `manage-bookmarks`
- **Data Flow Analysis**: `analyze-data-flow`
- **Call Analysis**: `get-call-graph`
- **Constant Search**: `search-constants`
- **Advanced Analysis**: `analyze-vtables`

Each tool uses mode/action enums and optional parameters to provide flexible functionality, reducing LLM context size and improving tool selection reliability.

## 💡 Usage Tips

### Start with High-Level Analysis

Begin by understanding the binary structure:

```txt
List all functions in the program and show me the main function's call graph
```

### Trace Data Flow

Understand how data moves through the program:

```txt
Trace data flow backward from address 0x401234 to find where the value comes from
```

### Find Patterns

Search for specific patterns:

```txt
Find all uses of the constant 0xdeadbeef and show me where it's used
```

### Organize Findings

Use bookmarks to track important discoveries:

```txt
Set a bookmark at 0x401000 with type "Analysis" and comment "Encryption function"
```

### Analyze C++ Binaries

For C++ programs, analyze vtables:

```txt
Analyze the vtable at 0x405000 and find all potential callers of the virtual methods
```

### Manage Functions and Variables

Create and modify functions:

```txt
Create a function at 0x401000 named "my_function" and set its prototype to "int my_function(char* input)"
```

Rename and modify variables:

```txt
Rename variable "var1" to "input_buffer" in function "main" and change its type to "char*"
```

### Transfer Analysis Across Similar Binaries

Use function matching to transfer your analysis:

```txt
Match and transfer function "main" from program1.exe to program2.exe, then match and transfer all function names and tags from program1.exe to program2.exe
```
