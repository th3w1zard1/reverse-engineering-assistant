# ReVA Tools Reference

**26 tools** that provide comprehensive reverse engineering capabilities through intelligent parameterization. This design reduces LLM context overhead, improves tool selection reliability, and maintains 100% feature coverage. Each tool uses enums, optional parameters, and defaults to provide flexible, powerful functionality.

## GUI Mode Support

**Important:** In GUI mode, the `programPath` parameter is **optional** for most tools. When `programPath` is not provided, ReVa automatically uses the currently active program in the Ghidra Code Browser. This makes interactive analysis more convenient - you can simply call tools without specifying which program to use, and ReVa will operate on the program you're currently viewing.

**GUI-specific tools:**
- `get-current-program` - Get information about the currently active program
- `get-current-address` - Get the address currently selected in the Code Browser
- `get-current-function` - Get the function currently selected in the Code Browser

**Note:** In headless mode (when running without a GUI), `programPath` is still required for tools that operate on programs.

## Tool List

### 1. `manage-symbols`

Symbol and label management tool that replaces: `list_classes`, `list_namespaces`, `list_imports`, `list_exports`, `create_label`, `get_symbols`, `get_symbols_count`, `rename_data`

Symbols make code readable - instead of seeing `0x401234`, you see `main` or `encrypt_data`. Symbols include:
- **Function names** (e.g., `main`, `encrypt_password`)
- **Variable names** (e.g., `user_input`, `buffer`)
- **Data labels** (e.g., `g_config`, `error_strings`)
- **Import/export names** (functions imported from DLLs or exported by the binary)
- **Class/namespace names** (C++ classes, namespaces)

This tool provides 8 different modes to work with symbols, from discovering what the binary uses (imports/exports) to organizing your analysis (creating labels, renaming data).

#### Mode: `imports` - Discover External Dependencies

**What it does:** Lists all functions imported from external libraries (DLLs, shared objects). This is crucial for understanding what the binary depends on and what capabilities it might have.

**Use cases:**
- Initial binary triage: "What libraries does this malware use?"
- Understanding functionality: "Does it use crypto libraries? Network libraries?"
- Finding suspicious imports: "Why does a text editor import `VirtualAlloc`?"

**Example:**
```json
{
  "mode": "imports",
  "library_filter": "kernel32",
  "group_by_library": true
}
```

**Returns:** JSON grouped by library, showing function names, addresses, and library names. Example:
```json
{
  "libraries": [
    {
      "library": "KERNEL32.DLL",
      "functions": [
        {"name": "CreateFileA", "address": "0x401000"},
        {"name": "ReadFile", "address": "0x401010"}
      ]
    }
  ],
  "totalCount": 45
}
```

**Parameters:**
- `library_filter` (optional): Filter to specific library (e.g., "kernel32.dll", "msvcrt.dll"). Case-insensitive.
- `group_by_library` (default: true): When true, groups imports by library. When false, returns flat list.
- `max_results` (default: 500): Maximum imports to return (useful for binaries with hundreds of imports).
- `start_index` (default: 0): For pagination - skip first N results.

#### Mode: `exports` - Find Exported Functions

**What it does:** Lists all functions exported by the binary. Only relevant for DLLs/shared libraries that export functions for other programs to use.

**Use cases:**
- Analyzing DLLs: "What functions does this DLL export?"
- Understanding library APIs: "What's the public interface of this library?"
- Finding entry points: "What functions can other programs call?"

**Example:**
```json
{
  "mode": "exports",
  "max_results": 100
}
```

**Returns:** JSON list of exported functions with names, addresses, and ordinal numbers.

#### Mode: `classes` - Find C++ Classes

**What it does:** Lists all C++ class names found in the binary. Useful for understanding object-oriented code structure.

**Use cases:**
- C++ reverse engineering: "What classes does this binary define?"
- Understanding architecture: "What's the class hierarchy?"
- Finding specific classes: "Is there a `CryptoManager` class?"

**Example:**
```json
{
  "mode": "classes",
  "start_index": 0,
  "limit": 50
}
```

**Returns:** Paginated list of class names. Example:
```json
{
  "classes": ["CryptoManager", "NetworkHandler", "UserAuthenticator"],
  "totalCount": 12,
  "hasMore": false
}
```

#### Mode: `namespaces` - Find C++ Namespaces

**What it does:** Lists all C++ namespace names (excluding the global namespace). Namespaces organize code and prevent naming conflicts.

**Use cases:**
- C++ code organization: "What namespaces are used?"
- Finding related code: "All code in `namespace::crypto` is related"
- Understanding code structure: "How is the code organized?"

**Example:**
```json
{
  "mode": "namespaces"
}
```

**Returns:** Paginated list of namespace names.

#### Mode: `symbols` - Get All Symbols with Details

**What it does:** Retrieves detailed information about symbols in the program (functions, variables, labels) with full metadata.

**Use cases:**
- Comprehensive analysis: "Show me all named things in this binary"
- Finding specific symbols: "Is there a symbol named `decrypt`?"
- Understanding symbol organization: "What symbols are in namespace X?"

**Example:**
```json
{
  "mode": "symbols",
  "max_count": 100,
  "filter_default_names": true,
  "include_external": false
}
```

**Returns:** JSON array of symbol objects with:
- `name`: Symbol name
- `address`: Memory address (hex string)
- `namespace`: Parent namespace
- `symbolType`: Type (FUNCTION, LABEL, etc.)
- `id`: Unique symbol ID

**Parameters:**
- `filter_default_names` (default: true): When true, excludes Ghidra auto-generated names like `FUN_00401000`, `DAT_00402000`. Set to false to see everything.
- `include_external` (default: false): When true, includes external symbols (imports). Usually you want false to see only symbols defined in this binary.
- `max_count` (default: 200): Maximum symbols to return.
- `start_index` (default: 0): Pagination offset.

#### Mode: `count` - Count Symbols

**What it does:** Returns the total count of symbols in the program. Useful before pagination to know how many symbols exist.

**Use cases:**
- Planning pagination: "How many symbols total? Should I paginate?"
- Quick assessment: "Does this binary have many symbols (well-analyzed) or few (needs work)?"
- Progress tracking: "How many symbols have I named so far?"

**Example:**
```json
{
  "mode": "count",
  "filter_default_names": true,
  "include_external": false
}
```

**Returns:** JSON with total count. Example:
```json
{
  "totalCount": 1247,
  "filteredCount": 856
}
```

#### Mode: `create_label` - Add Human-Readable Names

**What it does:** Creates a label (symbol name) at a specific memory address. This is how you name things during analysis - turning `0x401234` into `user_input_buffer`.

**Use cases:**
- Naming important addresses: "This address at 0x401000 is the encryption key, label it `encryption_key`"
- Organizing analysis: "Label all these addresses with descriptive names"
- Batch labeling: "Label all addresses in this array with meaningful names"

**Example (single label):**
```json
{
  "mode": "create_label",
  "address": "0x401234",
  "label_name": "user_input_buffer"
}
```

**Example (batch - create multiple labels):**
```json
{
  "mode": "create_label",
  "address": ["0x401000", "0x401010", "0x401020"],
  "label_name": ["config_data", "error_handler", "main_loop"]
}
```

**Returns:** Success message with label name and address. For batch operations, returns array of results with success/failure for each.

**Parameters:**
- `address` (required): Single address string or array of addresses for batch operations.
- `label_name` (required): Single name string or array of names matching address array.

**Note:** If `label_name` is not provided and auto-labeling is enabled (via environment variable), the tool will attempt to suggest a name based on context.

#### Mode: `rename_data` - Rename Existing Data Labels

**What it does:** Renames an existing data label at a specific address. Useful for improving names as you learn more about what data represents.

**Use cases:**
- Improving names: "I called this `data_1` but now I know it's `user_credentials`, rename it"
- Batch renaming: "Rename all these poorly-named labels to better names"
- Standardizing names: "Rename all `temp_*` labels to follow naming convention"

**Example (single rename):**
```json
{
  "mode": "rename_data",
  "address": "0x402000",
  "new_name": "encryption_key"
}
```

**Example (batch rename):**
```json
{
  "mode": "rename_data",
  "address": ["0x401000", "0x401010"],
  "new_name": ["config_struct", "error_code"]
}
```

**Returns:** Success message with old name, new name, and address.

**Parameters:**
- `address` (required): Address of data to rename (single string or array for batch).
- `new_name` (required): New name for the label (single string or array matching address array).

---

**Common Parameter Notes:**

- **Pagination:** Use `start_index` and `limit` (or `max_count`) together to paginate through large results:
  - First page: `start_index=0, limit=100`
  - Second page: `start_index=100, limit=100`
  - Third page: `start_index=200, limit=100`

- **Backward compatibility:** The tool accepts both `start_index`/`max_count` (new) and `offset`/`limit` (old) parameter names. Use whichever you prefer.

- **Filtering default names:** `filter_default_names=true` (default) hides Ghidra's auto-generated names like `FUN_00401000`. Set to `false` to see everything, including unnamed addresses that Ghidra assigned temporary names.

- **External symbols:** `include_external=false` (default) shows only symbols defined in this binary. Set to `true` to also include imported functions from DLLs.

### 2. `manage-strings`

String listing, searching, and analysis tool that replaces: `list_strings`, `get_strings`, `search_strings_regex`, `get_strings_count`, `get_strings_by_similarity`

List, search, count, or find similar strings in the program.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, optional): Operation mode enum ('list', 'regex', 'count', 'similarity'; default: 'list')
- `pattern` (string, optional): Regular expression pattern to search for when mode='regex' (required for regex mode)
- `search_string` (string, optional): String to compare against for similarity when mode='similarity' (required for similarity mode)
- `filter` (string, optional): Optional filter to match within string content when mode='list'
- `start_index` (integer, optional): Starting index for pagination when mode='list' or 'similarity' (0-based, default: 0)
- `max_count` (integer, optional): Maximum number of strings to return when mode='list' or 'similarity' (default: 100)
- `offset` (integer, optional): Alternative pagination offset when mode='list' (default: 0, used for backward compatibility)
- `limit` (integer, optional): Alternative pagination limit when mode='list' (default: 2000, used for backward compatibility)
- `max_results` (integer, optional): Maximum number of results to return when mode='regex' (default: 100)
- `include_referencing_functions` (boolean, optional): Include list of functions that reference each string when mode='list' or 'similarity' (default: False)

**Returns:**
- When mode='list': JSON with strings list and pagination info, or list of strings with their addresses
- When mode='regex': List of strings matching the regex pattern
- When mode='count': Total number of defined strings
- When mode='similarity': JSON with matching strings sorted by similarity

### 3. `list-functions`

Comprehensive function listing and search tool that replaces: `list-functions`, `list_methods`, `search_functions_by_name`, `get_functions_by_similarity`, `get_undefined_function_candidates`, `get_function_count`

List, search, or count functions in the program with various filtering and search modes.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, optional): Operation mode enum ('all', 'search', 'similarity', 'undefined', 'count'; default: 'all')
- `query` (string, optional): Substring to search for when mode='search' (required for search mode)
- `search_string` (string, optional): Function name to compare against for similarity when mode='similarity' (required for similarity mode)
- `min_reference_count` (integer, optional): Minimum number of references required when mode='undefined' (default: 1)
- `start_index` (integer, optional): Starting index for pagination (0-based, default: 0)
- `max_count` (integer, optional): Maximum number of functions to return (default: 100)
- `offset` (integer, optional): Alternative pagination offset parameter (default: 0, used for backward compatibility)
- `limit` (integer, optional): Alternative pagination limit parameter (default: 100, used for backward compatibility)
- `filter_default_names` (boolean, optional): Whether to filter out default Ghidra generated names like FUN_, DAT_, etc. (default: True)

**Returns:**
- When mode='all': List of all function names with pagination
- When mode='search': List of functions whose name contains the query substring
- When mode='similarity': JSON with matching functions sorted by similarity to search_string
- When mode='undefined': JSON with undefined function candidates (addresses referenced but not defined as functions)
- When mode='count': JSON with total function count

### 4. `manage-function`

Function manipulation tool that replaces: `create_function`, `rename_function`, `rename_function_by_address`, `set_function_prototype`

Create, rename, or modify function signatures.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum ('create', 'rename_function', 'set_prototype')
- `address` (string, optional): Address where the function should be created when action='create' (e.g., '0x401000', required for create)
- `function_identifier` (string or array, optional): Function name or address for rename/modify operations. Can be a single string or an array of strings for batch operations (required for rename_function, set_prototype)
- `name` (string, optional): New function name when action='rename_function' or optional name when action='create' (optional, not used in batch mode)
- `functions` (array, optional): Array of function rename objects for batch renaming. Each object should have 'function_identifier' (required) and 'name' (required). When provided with action='rename_function', renames multiple functions in a single transaction.
- `prototype` (string, optional): Function prototype/signature string when action='set_prototype' (required for set_prototype)
- `createIfNotExists` (boolean, optional): Create function if it doesn't exist when action='set_prototype' (default: true)

**Returns:**
- When action='create': JSON with created function information
- When action='rename_function': Success message with renamed function details
- When action='set_prototype': JSON with updated function information including parsed signature

### 5. `manage-variable`

Variable manipulation tool that replaces: `rename_variable`, `rename_variables`, `set_local_variable_type`, `change_variable_datatypes`

Rename variables or modify variable data types within functions.

**Args:**
- `programPath` (string, required): Path in the Ghidra Project to the program
- `action` (string, required): Action to perform enum ('rename_variable', 'set_variable_type', 'change_datatypes')
- `function_identifier` (string, required): Function name or address for variable operations
- `old_name` (string, optional): Old variable name when action='rename_variable' (required for single variable rename)
- `new_name` (string, optional): New variable name when action='rename_variable' (required for single variable rename)
- `variable_mappings` (string, optional): Mapping of old to new variable names when action='rename_variable' (format: "oldName1:newName1,oldName2:newName2", required for multiple variables)
- `variable_name` (string, optional): Variable name when action='set_variable_type' (required for set_variable_type)
- `new_type` (string, optional): New data type for variable when action='set_variable_type' (required for set_variable_type)
- `datatype_mappings` (string, optional): Mapping of variable names to new data type strings when action='change_datatypes' (format: "varName1:type1,varName2:type2", required for change_datatypes)
- `archive_name` (string, optional): Optional name of the data type archive to search for data types when action='change_datatypes' (optional, default: "")

**Returns:**
- When action='rename_variable': JSON with success status, renamed count, and decompilation diff
- When action='set_variable_type': JSON with success status and updated variable information
- When action='change_datatypes': JSON with success status, changed count, errors (if any), and decompilation diff

### 6. `manage-function-tags`

Function tag management tool that replaces: `function_tags`

Manage function tags to categorize functions (e.g., 'AI', 'rendering'). Tags can be retrieved, set, added, removed, or listed.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `function` (string, optional): Function name or address (required for get/set/add/remove modes, not required for list mode)
- `mode` (string, required): Operation mode enum ('get', 'set', 'add', 'remove', 'list')
- `tags` (string, optional): Tag names (required for add mode; optional for set/remove modes). Comma-separated format (e.g., "AI,rendering,encryption")

**Returns:**
- When mode='get': JSON with tag information for the specified function
- When mode='set': Success message after replacing all tags on the function
- When mode='add': Success message after adding tags to the function
- When mode='remove': Success message after removing tags from the function
- When mode='list': JSON with all tags in the program

### 7. `inspect-memory`

Memory and data inspection tool that replaces: `get_memory_blocks`, `read_memory`, `get_data_at_address`, `list_data_items`, `list_segments`

Inspect memory blocks, read memory, get data information, list data items, or list memory segments.

**Args:**
- `programPath` (string, required): Path in the Ghidra Project to the program
- `mode` (string, required): Inspection mode enum ('blocks', 'read', 'data_at', 'data_items', 'segments')
- `address` (string, optional): Address to read from when mode='read' or address to query when mode='data_at' (required for read/data_at modes)
- `length` (integer, optional): Number of bytes to read when mode='read' (default: 16)
- `offset` (integer, optional): Pagination offset when mode='data_items' or 'segments' (default: 0)
- `limit` (integer, optional): Maximum number of items to return when mode='data_items' or 'segments' (default: 100)

**Returns:**
- When mode='blocks': List of memory blocks with their properties (R/W/X, size, etc.)
- When mode='read': Hex dump of memory content with ASCII representation
- When mode='data_at': Data type, size, label, and value information
- When mode='data_items': List of defined data labels and their values
- When mode='segments': List of all memory segments in the program

### 8. `open`

Unified tool that opens either a Ghidra project (.gpr file) or a program file. Automatically detects the type based on the path extension. Also supports bulk operations to open multiple programs by extension.

**For projects (.gpr files):**
- Opens the project and optionally loads all programs into memory

**For programs (any other file):**
- Imports if missing, opens if exists
- Always saves to project and caches for other tools

**For bulk operations (extensions provided):**
- Opens all programs matching the specified extensions in Code Browser

**Args:**
- `path` (string, optional): Path to open: a Ghidra project file (.gpr), a program file, or a project folder path. If extensions is provided, this is treated as a folder path (default: '/'). If .gpr, opens the project. Otherwise, imports/opens the program in the active project.
- `extensions` (string, optional): Optional: comma-separated list of file extensions to open (e.g., 'exe,dll' or 'exe'). If provided, opens all matching programs in Code Browser instead of opening a single file. Defaults to 'exe,dll' when extensions is provided. Ignored if not provided.
- `openAllPrograms` (boolean, optional): For projects: whether to automatically open all programs into memory (default: true). Ignored for program files or when extensions is provided.
- `destinationFolder` (string, optional): For programs: project folder for new imports (default: '/'). Ignored for projects, bulk operations, or if program exists.
- `analyzeAfterImport` (boolean, optional): For programs: run auto-analysis on new imports (default: true). Ignored for projects, bulk operations, or if program exists.
- `enableVersionControl` (boolean, optional): For programs: add new imports to version control (default: true). Ignored for projects, bulk operations, or if program exists.
- `serverUsername` (string, optional): For shared projects: Username for Ghidra Server authentication. If not provided, will check REVA_SERVER_USERNAME environment variable. Required for shared projects connected to a Ghidra Server.
- `serverPassword` (string, optional): For shared projects: Password for Ghidra Server authentication. If not provided, will check REVA_SERVER_PASSWORD environment variable. Required for shared projects connected to a Ghidra Server.
- `serverHost` (string, optional): For shared projects: Ghidra Server hostname or IP address. If not provided, will check REVA_SERVER_HOST environment variable. Note: Server address is typically stored in the project file. This parameter may be used if the server has moved or to override the stored address.
- `serverPort` (integer, optional): For shared projects: Ghidra Server port (default: 13100). If not provided, will check REVA_SERVER_PORT environment variable. Note: Server port is typically stored in the project file. This parameter may be used if the server port has changed or to override the stored port.

**Returns:**
- For projects: JSON with project information including project name, location, program count, and list of opened programs (if openAllPrograms=true)
- For programs: JSON with program information including programPath, wasImported status, and program metadata
- For bulk operations: JSON with list of opened programs and their status

### 9. `list-project-files`

List files and folders in the Ghidra project.

**Args:**
- `folderPath` (string, required): Path to the folder to list contents of. Use '/' for the root folder.
- `recursive` (boolean, optional): Whether to list files recursively (default: false)

**Returns:**
- JSON with folder metadata and list of files/folders with their properties (type, path, lastModified, versioned status, etc.)

### 10. `list-open-programs`

List all currently open programs in the Ghidra project.

**Args:**
- None (tool requires no parameters)

**Returns:**
- JSON with list of open programs including programPath, name, language, compiler spec, size, function count, and symbol count

### 11. `get-current-program`

Get information about the currently active program in Ghidra. In GUI mode, this returns the program currently open in the Code Browser.

**Args:**
- None (tool requires no parameters)

**Returns:**
- JSON with current program information including programPath, name, language, compiler spec, size, function count, and symbol count, or null if no program is active

### 11a. `get-current-address` (GUI Mode Only)

Get the address currently selected by the user in the Code Browser. This tool is only available in GUI mode.

**Args:**
- None (tool requires no parameters)

**Returns:**
- JSON with the currently selected address and programPath, or an error if no address is currently selected

### 11b. `get-current-function` (GUI Mode Only)

Get the function currently selected by the user in the Code Browser. This tool is only available in GUI mode.

**Args:**
- None (tool requires no parameters)

**Returns:**
- JSON with the currently selected function information including functionName, address, signature, and programPath, or an error if no function is at the current location

### 12. `checkin-program`

Checkin (commit) a program to version control with a commit message.

**Args:**
- `programPath` (string, required): Path to the program to checkin (e.g., '/Hatchery.exe')
- `message` (string, required): Commit message for the checkin
- `keepCheckedOut` (boolean, optional): Whether to keep the program checked out after checkin (default: false)

**Returns:**
- JSON with success status, action taken (added_to_version_control, checked_in, or saved), and version control status

### 13. `analyze-program`

Run Ghidra's auto-analysis on a program.

**Args:**
- `programPath` (string, required): Path to the program to analyze (e.g., '/Hatchery.exe')

**Returns:**
- JSON with success status and analysis status

### 14. `change-processor`

Change the processor architecture of an existing program.

**Args:**
- `programPath` (string, required): Path to the program to modify (e.g., '/Hatchery.exe')
- `languageId` (string, required): Language ID for the new processor (e.g., 'x86:LE:64:default')
- `compilerSpecId` (string, optional): Compiler spec ID (optional, defaults to the language's default)

**Returns:**
- JSON with success status, old language, and new language/compiler spec information

### 15. `manage-files`

Import files into the Ghidra project or export program data to files.

**Args:**
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
- `export_type` (string, optional): For export: Type of export: 'program' (export binary), 'function_info' (export function information as JSON/CSV), 'strings' (export strings as text)
- `format` (string, optional): For export: Export format for function_info: 'json' or 'csv' (default: 'json')
- `include_parameters` (boolean, optional): For export: Include function parameters in function_info export (default: true)
- `include_variables` (boolean, optional): For export: Include local variables in function_info export (default: true)
- `include_comments` (boolean, optional): For export: Include comments in function_info export (default: false)

**Returns:**
- For import: JSON with import results including files discovered, programs imported, files analyzed, and files added to version control
- For export: JSON with export success status and file path

### 16. `get-references`

Comprehensive cross-reference analysis tool that replaces: `get_xrefs_to`, `get_xrefs_from`, `find_cross_references`, `get_function_xrefs`, `get_referencers_decompiled`, `find_import_references`, `resolve_thunk`

Find and analyze references to/from addresses, symbols, functions, or imports, with optional decompilation of referencers.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `target` (string, required): Target address, symbol name, function name, or import name
- `mode` (string, optional): Reference mode enum ('to', 'from', 'both', 'function', 'referencers_decomp', 'import', 'thunk'; default: 'both')
- `direction` (string, optional): Direction filter when mode='both' enum ('to', 'from', 'both'; default: 'both')
- `offset` (integer, optional): Pagination offset (default: 0)
- `limit` (integer, optional): Maximum number of references to return (default: 100)
- `max_results` (integer, optional): Alternative limit parameter for import mode (default: 100)
- `library_name` (string, optional): Optional specific library name to narrow search when mode='import' (case-insensitive)
- `start_index` (integer, optional): Starting index for pagination when mode='referencers_decomp' (0-based, default: 0)
- `max_referencers` (integer, optional): Maximum number of referencing functions to decompile when mode='referencers_decomp' (default: 10)
- `include_ref_context` (boolean, optional): Whether to include reference line numbers in decompilation when mode='referencers_decomp' (default: True)
- `include_data_refs` (boolean, optional): Whether to include data references (reads/writes), not just calls when mode='referencers_decomp' (default: True)

**Returns:**
- When mode='to': List of references TO the specified address
- When mode='from': List of references FROM the specified address
- When mode='both': List of cross-references in both directions
- When mode='function': List of references to the specified function by name
- When mode='referencers_decomp': JSON with decompiled referencers
- When mode='import': JSON with references to the imported function
- When mode='thunk': JSON with thunk chain information

### 17. `manage-data-types`

Data type management tool that replaces: `get_data_type_archives`, `get_data_types`, `get_data_type_by_string`, `apply_data_type`

Get data type archives, list data types, get data type by string representation, or apply data types to addresses/symbols.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum ('archives', 'list', 'by_string', 'apply')
- `archive_name` (string, optional): Name of the data type archive when action='list', 'by_string', or 'apply' (required for list, optional for by_string/apply)
- `category_path` (string, optional): Path to category to list data types from when action='list' (e.g., '/Structure', use '/' for root, default: '/')
- `include_subcategories` (boolean, optional): Whether to include data types from subcategories when action='list' (default: False)
- `start_index` (integer, optional): Starting index for pagination when action='list' (0-based, default: 0)
- `max_count` (integer, optional): Maximum number of data types to return when action='list' (default: 100)
- `data_type_string` (string, optional): String representation of the data type when action='by_string' or 'apply' (e.g., 'char**', 'int[10]', required for by_string/apply)
- `address_or_symbol` (string, optional): Address or symbol name to apply the data type to when action='apply' (required for apply)

**Returns:**
- When action='archives': JSON with data type archives
- When action='list': JSON with data types
- When action='by_string': JSON with data type information
- When action='apply': Success or failure message

### 18. `manage-structures`

Structure management tool that replaces: `parse_c_structure`, `validate_c_structure`, `create_structure`, `add_structure_field`, `modify_structure_field`, `modify_structure_from_c`, `get_structure_info`, `list_structures`, `apply_structure`, `delete_structure`, `parse_c_header`

Parse, validate, create, modify, query, list, apply, or delete structures. Also parse entire C header files.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum ('parse', 'validate', 'create', 'add_field', 'modify_field', 'modify_from_c', 'info', 'list', 'apply', 'delete', 'parse_header')
- `c_definition` (string, optional): C-style structure definition when action='parse', 'validate', or 'modify_from_c' (required for parse/validate/modify_from_c)
- `header_content` (string, optional): C header file content when action='parse_header' (required for parse_header)
- `structure_name` (string, optional): Name of the structure (required for add_field, modify_field, info, apply, delete; optional for list)
- `name` (string, optional): Name of the structure when action='create' (required for create)
- `size` (integer, optional): Initial size when action='create' (0 for auto-sizing, default: 0)
- `type` (string, optional): Structure type when action='create' enum ('structure', 'union'; default: 'structure')
- `category` (string, optional): Category path (default: '/')
- `packed` (boolean, optional): Whether structure should be packed when action='create' (default: False)
- `description` (string, optional): Description of the structure when action='create'
- `field_name` (string, optional): Name of the field when action='add_field' or 'modify_field' (required for add_field, optional for modify_field)
- `data_type` (string, optional): Data type when action='add_field' (e.g., 'int', 'char[32]', required for add_field)
- `offset` (integer, optional): Field offset when action='add_field' or 'modify_field' (optional, omit to append for add_field)
- `comment` (string, optional): Field comment when action='add_field'
- `new_data_type` (string, optional): New data type for the field when action='modify_field'
- `new_field_name` (string, optional): New name for the field when action='modify_field'
- `new_comment` (string, optional): New comment for the field when action='modify_field'
- `new_length` (integer, optional): New length for the field when action='modify_field' (advanced, optional)
- `address_or_symbol` (string, optional): Address or symbol name to apply structure when action='apply' (required for apply)
- `clear_existing` (boolean, optional): Clear existing data when action='apply' (default: True)
- `force` (boolean, optional): Force deletion even if structure is referenced when action='delete' (default: False)
- `name_filter` (string, optional): Filter by name (substring match) when action='list'
- `include_built_in` (boolean, optional): Include built-in types when action='list' (default: False)

**Returns:**
- When action='parse': JSON with created structure info
- When action='validate': JSON with validation result
- When action='create': JSON with created structure info
- When action='add_field': JSON with success status
- When action='modify_field': JSON with success status
- When action='modify_from_c': JSON with success status
- When action='info': JSON with structure info including all fields
- When action='list': JSON with list of structures
- When action='apply': JSON with success status
- When action='delete': JSON with success status or reference warnings
- When action='parse_header': JSON with created types info

### 19. `manage-comments`

Comment management and search tool that replaces: `set_decompiler_comment`, `set_disassembly_comment`, `set_decompilation_comment`, `set_comment`, `get_comments`, `remove_comment`, `search_comments`, `search_decompilation`

Set, get, remove, or search comments in decompiled code, disassembly, or at addresses. Also search patterns across all decompilations.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum ('set', 'get', 'remove', 'search', 'search_decomp')
- `address` (string, optional): Address where to set/get/remove the comment (required for set/remove when not using function/line_number)
- `address_or_symbol` (string, optional): Address or symbol name (alternative parameter, used for set/get/remove)
- `function` (string, optional): Function name or address when setting decompilation line comment or searching decompilation (required for set with line_number, optional for search_decomp)
- `function_name_or_address` (string, optional): Function name or address (alternative parameter name)
- `line_number` (integer, optional): Line number in the decompiled function when action='set' with decompilation (1-based, required for decompilation line comments)
- `comment` (string, optional): The comment text to set (required for set)
- `comment_type` (string, optional): Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable'; default: 'eol')
- `start` (string, optional): Start address of the range when action='get'
- `end` (string, optional): End address of the range when action='get'
- `comment_types` (string, optional): Types of comments to retrieve/search (comma-separated: pre,eol,post,plate,repeatable)
- `search_text` (string, optional): Text to search for in comments when action='search' (required for search)
- `pattern` (string, optional): Regular expression pattern to search for when action='search_decomp' (required for search_decomp)
- `case_sensitive` (boolean, optional): Whether search is case sensitive when action='search' or 'search_decomp' (default: False)
- `max_results` (integer, optional): Maximum number of results to return when action='search' or 'search_decomp' (default: 100 for search, 50 for search_decomp)
- `override_max_functions_limit` (boolean, optional): Whether to override the maximum function limit for decompiler searches when action='search_decomp' (default: False)

**Returns:**
- When action='set': Success or failure message, or JSON with success status for decompilation line comments
- When action='get': JSON with comments
- When action='remove': Success or failure message
- When action='search': JSON with matching comments
- When action='search_decomp': JSON with search results from decompiled functions

### 20. `manage-bookmarks`

Bookmark management tool that replaces: `set_bookmark`, `get_bookmarks`, `search_bookmarks`, `remove_bookmark`, `list_bookmark_categories`

Create, retrieve, search, remove bookmarks, or list bookmark categories.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `action` (string, required): Action to perform enum ('set', 'get', 'search', 'remove', 'categories')
- `address` (string, optional): Address where to set/get/remove the bookmark (required for set/remove, optional for get)
- `address_or_symbol` (string, optional): Address or symbol name (alternative parameter name, used for remove action)
- `type` (string, optional): Bookmark type enum ('Note', 'Warning', 'TODO', 'Bug', 'Analysis'; required for set/remove, optional for get/categories)
- `category` (string, optional): Bookmark category for organization (required for set, optional for remove)
- `comment` (string, optional): Bookmark comment text (required for set)
- `search_text` (string, optional): Text to search for in bookmark comments when action='search' (required for search)
- `max_results` (integer, optional): Maximum number of results to return when action='search' (default: 100)

**Returns:**
- When action='set': Success or failure message
- When action='get': List of bookmarks
- When action='search': List of matching bookmarks
- When action='remove': Success or failure message
- When action='categories': JSON with bookmark categories

### 21. `analyze-data-flow`

Data flow analysis tool that replaces: `trace_data_flow_backward`, `trace_data_flow_forward`, `find_variable_accesses`

Trace data flow backward (origins), forward (uses), or find variable accesses within a function.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `function_address` (string, required): Address of the function to analyze
- `start_address` (string, optional): Address within the function to trace from when direction='backward' or 'forward' (required for backward/forward)
- `variable_name` (string, optional): Name of the variable to find accesses for when direction='variable_accesses' (required for variable_accesses)
- `direction` (string, required): Analysis direction enum ('backward', 'forward', 'variable_accesses')

**Returns:**
- When direction='backward': Data flow information showing where values come from
- When direction='forward': Data flow information showing where values are used
- When direction='variable_accesses': List of variable accesses (reads and writes)

### 22. `get-call-graph`

Call graph and relationship analysis tool that replaces: `get-call-graph`, `get_call_tree`, `get_function_callers`, `get_function_callees`, `get_callers_decompiled`, `find_common_callers`

Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees, caller/callee lists, decompiled callers, or common callers.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `function_identifier` (string, required): Function name or address
- `mode` (string, optional): Analysis mode enum ('graph', 'tree', 'callers', 'callees', 'callers_decomp', 'common_callers'; default: 'graph')
- `depth` (integer, optional): Depth of call graph to retrieve when mode='graph' (default: 1)
- `direction` (string, optional): Direction to traverse when mode='tree' or 'callers' or 'callees' enum ('callers', 'callees'; default: 'callees' for tree)
- `max_depth` (integer, optional): Maximum depth to traverse when mode='tree' (default: 3, max: 10)
- `start_index` (integer, optional): Starting index for pagination when mode='callers_decomp' (0-based, default: 0)
- `max_callers` (integer, optional): Maximum number of calling functions to decompile when mode='callers_decomp' (default: 10)
- `include_call_context` (boolean, optional): Whether to highlight the line containing the call in each decompilation when mode='callers_decomp' (default: True)
- `function_addresses` (string, optional): Comma-separated list of function addresses or names when mode='common_callers' (required for common_callers mode)

**Returns:**
- When mode='graph': Call graph information showing both callers and callees
- When mode='tree': Hierarchical call tree as formatted text
- When mode='callers': List of functions that call the specified function
- When mode='callees': List of functions called by the specified function
- When mode='callers_decomp': JSON with decompiled callers
- When mode='common_callers': List of functions that call ALL of the specified target functions

### 23. `search-constants`

Constant value search and analysis tool that replaces: `find_constant_uses`, `find_constants_in_range`, `list_common_constants`

Find specific constants, constants in ranges, or list the most common constants in the program.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, required): Search mode enum ('specific', 'range', 'common')
- `value` (string, optional): Constant value to search for when mode='specific' (supports hex with 0x, decimal, negative; required for specific mode)
- `min_value` (string, optional): Minimum value when mode='range' or filter minimum when mode='common' (inclusive, supports hex/decimal; required for range mode)
- `max_value` (string, optional): Maximum value when mode='range' (inclusive, supports hex/decimal; required for range mode)
- `max_results` (integer, optional): Maximum number of results to return when mode='specific' or 'range' (default: 500)
- `include_small_values` (boolean, optional): Include small values (0-255) which are often noise when mode='common' (default: False)
- `top_n` (integer, optional): Number of most common constants to return when mode='common' (default: 50)

**Returns:**
- When mode='specific': List of instructions using the constant
- When mode='range': List of constants found in the range with occurrence counts
- When mode='common': JSON with most common constants

### 24. `analyze-vtables`

Virtual function table analysis tool that replaces: `analyze_vtable`, `find_vtable_callers`, `find_vtables_containing_function`

Analyze vtables, find vtable callers, or find vtables containing a specific function.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `mode` (string, required): Analysis mode enum ('analyze', 'callers', 'containing')
- `vtable_address` (string, optional): Address of the vtable to analyze when mode='analyze' (required for analyze mode)
- `function_address` (string, optional): Address or name of the virtual function when mode='callers' or function to search for when mode='containing' (required for callers/containing modes)
- `max_entries` (integer, optional): Maximum number of vtable entries to read when mode='analyze' (default: 200)

**Returns:**
- When mode='analyze': Vtable structure with function pointers and slot information
- When mode='callers': List of potential caller sites for the virtual method
- When mode='containing': JSON with vtables containing the function

### 25. `get-function`

Unified function retrieval tool that replaces: `decompile_function`, `decompile_function_by_address`, `get_decompilation`, `disassemble_function`, `get_function_by_address`, `get_function_info`, `list_function_calls`

Get function details in various formats: decompiled code, assembly, function information, or internal calls.

**Args:**
- `programPath` (string, optional): Path in the Ghidra Project to the program. Optional in GUI mode - if not provided, uses the currently active program in the Code Browser.
- `identifier` (string, required): Function name or address - accepts either function name or hex address (e.g., "main" or "0x401000")
- `view` (string, optional): View mode enum ('decompile', 'disassemble', 'info', 'calls'; default: 'decompile')
- `offset` (integer, optional): Line number to start reading from when view='decompile' (1-based, default: 1)
- `limit` (integer, optional): Number of lines to return when view='decompile' (default: 50)
- `include_callers` (boolean, optional): Include list of functions that call this one when view='decompile' (default: False)
- `include_callees` (boolean, optional): Include list of functions this one calls when view='decompile' (default: False)
- `include_comments` (boolean, optional): Whether to include comments in the decompilation when view='decompile' (default: False)
- `include_incoming_references` (boolean, optional): Whether to include incoming cross references when view='decompile' (default: True)
- `include_reference_context` (boolean, optional): Whether to include code context snippets from calling functions when view='decompile' (default: True)

**Returns:**
- When view='decompile': JSON with decompiled C code and optional metadata
- When view='disassemble': List of assembly instructions (address: instruction; comment)
- When view='info': Detailed function information including parameters and local variables
- When view='calls': List of function calls made within the function

### 26. `capture-reva-debug-info`

Capture debug information from ReVa for troubleshooting purposes.

**Args:**
- None (tool requires no parameters)

**Returns:**
- JSON with debug information including server status, configuration, and diagnostic data

---

## 📊 Tool Consolidation Summary

The 26 tools above provide comprehensive reverse engineering capabilities:

- **Symbol Management**: `manage-symbols`
- **String Analysis**: `manage-strings`
- **Function Analysis**: `list-functions`, `manage-function`, `manage-variable`, `manage-function-tags`, `get-function`
- **Memory Inspection**: `inspect-memory`
- **Project Management**: `open`, `list-project-files`, `list-open-programs`, `get-current-program`, `get-current-address` (GUI), `get-current-function` (GUI), `checkin-program`, `analyze-program`, `change-processor`, `manage-files`, `capture-reva-debug-info`
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
