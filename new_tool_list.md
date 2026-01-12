# ReVA Tools Refactoring

**17 consolidated tools** that replace the original 90 tools through intelligent parameterization. This design reduces LLM context overhead, improves tool selection reliability, and maintains 100% feature coverage. Each tool uses enums, optional parameters, and defaults to provide flexible, powerful functionality.

## New Tool List

### 1. `get-function`

Unified function retrieval tool that replaces: `decompile_function`, `decompile_function_by_address`, `get_decompilation`, `disassemble_function`, `get_function_by_address`, `get_function_info`, `list_function_calls`

Get function details in various formats: decompiled code, assembly, function information, or internal calls.

Args:
    identifier: Function name or address (required) - accepts either function name or hex address (e.g., "main" or "0x401000")
    view: View mode enum ('decompile', 'disassemble', 'info', 'calls'; default: 'decompile')
    offset: Line number to start reading from when view='decompile' (1-based, default: 1)
    limit: Number of lines to return when view='decompile' (default: 50)
    include_callers: Include list of functions that call this one when view='decompile' (default: False)
    include_callees: Include list of functions this one calls when view='decompile' (default: False)
    include_comments: Whether to include comments in the decompilation when view='decompile' (default: False)
    include_incoming_references: Whether to include incoming cross references when view='decompile' (default: True)
    include_reference_context: Whether to include code context snippets from calling functions when view='decompile' (default: True)

Returns:
    - When view='decompile': JSON with decompiled C code and optional metadata
    - When view='disassemble': List of assembly instructions (address: instruction; comment)
    - When view='info': Detailed function information including parameters and local variables
    - When view='calls': List of function calls made within the function

### 2. `list-functions`

Comprehensive function listing and search tool that replaces: `list-functions`, `list_methods`, `search_functions_by_name`, `get_functions_by_similarity`, `get_undefined_function_candidates`, `get_function_count`

List, search, or count functions in the program with various filtering and search modes.

Args:
    mode: Operation mode enum ('all', 'search', 'similarity', 'undefined', 'count'; default: 'all')
    query: Substring to search for when mode='search' (required for search mode)
    search_string: Function name to compare against for similarity when mode='similarity' (required for similarity mode)
    min_reference_count: Minimum number of references required when mode='undefined' (default: 1)
    start_index: Starting index for pagination (0-based, default: 0)
    max_count: Maximum number of functions to return (default: 100)
    offset: Alternative pagination offset parameter (default: 0, used for backward compatibility)
    limit: Alternative pagination limit parameter (default: 100, used for backward compatibility)
    filter_default_names: Whether to filter out default Ghidra generated names like FUN_, DAT_, etc. (default: True)

Returns:
    - When mode='all': List of all function names with pagination
    - When mode='search': List of functions whose name contains the query substring
    - When mode='similarity': JSON with matching functions sorted by similarity to search_string
    - When mode='undefined': JSON with undefined function candidates (addresses referenced but not defined as functions)
    - When mode='count': JSON with total function count

### 3. `manage-function`

Function and variable manipulation tool that replaces: `create_function`, `rename_function`, `rename_function_by_address`, `rename_variable`, `rename_variables`, `set_function_prototype`, `set_local_variable_type`, `change_variable_datatypes`

Create, rename, or modify functions and their variables.

Args:
    action: Action to perform enum ('create', 'rename_function', 'rename_variable', 'set_prototype', 'set_variable_type', 'change_datatypes'; required)
    address: Address where the function should be created when action='create' (e.g., '0x401000', required for create)
    function_identifier: Function name or address for rename/modify operations (required for rename_function, rename_variable, set_prototype, set_variable_type, change_datatypes)
    name: New function name when action='rename_function' or optional name when action='create' (optional)
    old_name: Old variable name when action='rename_variable' (required for rename_variable)
    new_name: New variable name when action='rename_variable' (required for rename_variable)
    variable_mappings: Mapping of old to new variable names when action='rename_variable' (format: "oldName1:newName1,oldName2:newName2", required for rename_variable with multiple variables)
    prototype: Function prototype/signature string when action='set_prototype' (required for set_prototype)
    variable_name: Variable name when action='set_variable_type' (required for set_variable_type)
    new_type: New data type for variable when action='set_variable_type' (required for set_variable_type)
    datatype_mappings: Mapping of variable names to new data type strings when action='change_datatypes' (format: "varName1:type1,varName2:type2", required for change_datatypes)
    archive_name: Optional name of the data type archive to search for data types when action='change_datatypes' (optional, default: "")

Returns:
    Success or failure message for all actions

### 4. `get-call-graph`

Call graph and relationship analysis tool that replaces: `get-call-graph`, `get_call_tree`, `get_function_callers`, `get_function_callees`, `get_callers_decompiled`, `find_common_callers`

Analyze function call relationships in various formats: bidirectional graphs, hierarchical trees, caller/callee lists, decompiled callers, or common callers.

Args:
    function_identifier: Function name or address (required)
    mode: Analysis mode enum ('graph', 'tree', 'callers', 'callees', 'callers_decomp', 'common_callers'; default: 'graph')
    depth: Depth of call graph to retrieve when mode='graph' (default: 1)
    direction: Direction to traverse when mode='tree' or 'callers' or 'callees' enum ('callers', 'callees'; default: 'callees' for tree)
    max_depth: Maximum depth to traverse when mode='tree' (default: 3, max: 10)
    start_index: Starting index for pagination when mode='callers_decomp' (0-based, default: 0)
    max_callers: Maximum number of calling functions to decompile when mode='callers_decomp' (default: 10)
    include_call_context: Whether to highlight the line containing the call in each decompilation when mode='callers_decomp' (default: True)
    function_addresses: Comma-separated list of function addresses or names when mode='common_callers' (required for common_callers mode)

Returns:
    - When mode='graph': Call graph information showing both callers and callees
    - When mode='tree': Hierarchical call tree as formatted text
    - When mode='callers': List of functions that call the specified function
    - When mode='callees': List of functions called by the specified function
    - When mode='callers_decomp': JSON with decompiled callers
    - When mode='common_callers': List of functions that call ALL of the specified target functions

### 5. `get-references`

Comprehensive cross-reference analysis tool that replaces: `get_xrefs_to`, `get_xrefs_from`, `find_cross_references`, `get_function_xrefs`, `get_referencers_decompiled`, `find_import_references`, `resolve_thunk`

Find and analyze references to/from addresses, symbols, functions, or imports, with optional decompilation of referencers.

Args:
    target: Target address, symbol name, function name, or import name (required)
    mode: Reference mode enum ('to', 'from', 'both', 'function', 'referencers_decomp', 'import', 'thunk'; default: 'both')
    direction: Direction filter when mode='both' enum ('to', 'from', 'both'; default: 'both')
    offset: Pagination offset (default: 0)
    limit: Maximum number of references to return (default: 100)
    max_results: Alternative limit parameter for import mode (default: 100)
    library_name: Optional specific library name to narrow search when mode='import' (case-insensitive, optional)
    start_index: Starting index for pagination when mode='referencers_decomp' (0-based, default: 0)
    max_referencers: Maximum number of referencing functions to decompile when mode='referencers_decomp' (default: 10)
    include_ref_context: Whether to include reference line numbers in decompilation when mode='referencers_decomp' (default: True)
    include_data_refs: Whether to include data references (reads/writes), not just calls when mode='referencers_decomp' (default: True)

Returns:
    - When mode='to': List of references TO the specified address
    - When mode='from': List of references FROM the specified address
    - When mode='both': List of cross-references in both directions
    - When mode='function': List of references to the specified function by name
    - When mode='referencers_decomp': JSON with decompiled referencers
    - When mode='import': JSON with references to the imported function
    - When mode='thunk': JSON with thunk chain information

### 6. `analyze-data-flow`

Data flow analysis tool that replaces: `trace_data_flow_backward`, `trace_data_flow_forward`, `find_variable_accesses`

Trace data flow backward (origins), forward (uses), or find variable accesses within a function.

Args:
    function_address: Address of the function to analyze (required)
    start_address: Address within the function to trace from when direction='backward' or 'forward' (required for backward/forward)
    variable_name: Name of the variable to find accesses for when direction='variable_accesses' (required for variable_accesses)
    direction: Analysis direction enum ('backward', 'forward', 'variable_accesses'; required)

Returns:
    - When direction='backward': Data flow information showing where values come from
    - When direction='forward': Data flow information showing where values are used
    - When direction='variable_accesses': List of variable accesses (reads and writes)

### 7. `search-constants`

Constant value search and analysis tool that replaces: `find_constant_uses`, `find_constants_in_range`, `list_common_constants`

Find specific constants, constants in ranges, or list the most common constants in the program.

Args:
    mode: Search mode enum ('specific', 'range', 'common'; required)
    value: Constant value to search for when mode='specific' (supports hex with 0x, decimal, negative; required for specific mode)
    min_value: Minimum value when mode='range' or filter minimum when mode='common' (inclusive, supports hex/decimal; required for range mode)
    max_value: Maximum value when mode='range' (inclusive, supports hex/decimal; required for range mode)
    max_results: Maximum number of results to return when mode='specific' or 'range' (default: 500)
    include_small_values: Include small values (0-255) which are often noise when mode='common' (default: False)
    top_n: Number of most common constants to return when mode='common' (default: 50)

Returns:
    - When mode='specific': List of instructions using the constant
    - When mode='range': List of constants found in the range with occurrence counts
    - When mode='common': JSON with most common constants

### 8. `manage-strings`

String listing, searching, and analysis tool that replaces: `list_strings`, `get_strings`, `search_strings_regex`, `get_strings_count`, `get_strings_by_similarity`

List, search, count, or find similar strings in the program.

Args:
    mode: Operation mode enum ('list', 'regex', 'count', 'similarity'; default: 'list')
    pattern: Regular expression pattern to search for when mode='regex' (required for regex mode)
    search_string: String to compare against for similarity when mode='similarity' (required for similarity mode)
    filter: Optional filter to match within string content when mode='list' (optional)
    start_index: Starting index for pagination when mode='list' or 'similarity' (0-based, default: 0)
    max_count: Maximum number of strings to return when mode='list' or 'similarity' (default: 100)
    offset: Alternative pagination offset when mode='list' (default: 0, used for backward compatibility)
    limit: Alternative pagination limit when mode='list' (default: 2000, used for backward compatibility)
    max_results: Maximum number of results to return when mode='regex' (default: 100)
    include_referencing_functions: Include list of functions that reference each string when mode='list' or 'similarity' (default: False)

Returns:
    - When mode='list': JSON with strings list and pagination info, or list of strings with their addresses
    - When mode='regex': List of strings matching the regex pattern
    - When mode='count': Total number of defined strings
    - When mode='similarity': JSON with matching strings sorted by similarity

### 9. `inspect-memory`

Memory and data inspection tool that replaces: `get_memory_blocks`, `read_memory`, `get_data_at_address`, `list_data_items`, `list_segments`

Inspect memory blocks, read memory, get data information, list data items, or list memory segments.

Args:
    mode: Inspection mode enum ('blocks', 'read', 'data_at', 'data_items', 'segments'; required)
    address: Address to read from when mode='read' or address to query when mode='data_at' (required for read/data_at modes)
    length: Number of bytes to read when mode='read' (default: 16)
    offset: Pagination offset when mode='data_items' or 'segments' (default: 0)
    limit: Maximum number of items to return when mode='data_items' or 'segments' (default: 100)

Returns:
    - When mode='blocks': List of memory blocks with their properties (R/W/X, size, etc.)
    - When mode='read': Hex dump of memory content with ASCII representation
    - When mode='data_at': Data type, size, label, and value information
    - When mode='data_items': List of defined data labels and their values
    - When mode='segments': List of all memory segments in the program

### 10. `manage-bookmarks`

Bookmark management tool that replaces: `set_bookmark`, `get_bookmarks`, `search_bookmarks`, `remove_bookmark`, `list_bookmark_categories`

Create, retrieve, search, remove bookmarks, or list bookmark categories.

Args:
    action: Action to perform enum ('set', 'get', 'search', 'remove', 'categories'; required)
    address: Address where to set/get/remove the bookmark (required for set/remove, optional for get)
    address_or_symbol: Address or symbol name (alternative parameter name, used for remove action)
    type: Bookmark type enum ('Note', 'Warning', 'TODO', 'Bug', 'Analysis'; required for set/remove, optional for get/categories)
    category: Bookmark category for organization (required for set, optional for remove)
    comment: Bookmark comment text (required for set)
    search_text: Text to search for in bookmark comments when action='search' (required for search)
    max_results: Maximum number of results to return when action='search' (default: 100)

Returns:
    - When action='set': Success or failure message
    - When action='get': List of bookmarks
    - When action='search': List of matching bookmarks
    - When action='remove': Success or failure message
    - When action='categories': JSON with bookmark categories

### 11. `manage-comments`

Comment management and search tool that replaces: `set_decompiler_comment`, `set_disassembly_comment`, `set_decompilation_comment`, `set_comment`, `get_comments`, `remove_comment`, `search_comments`, `search_decompilation`

Set, get, remove, or search comments in decompiled code, disassembly, or at addresses. Also search patterns across all decompilations.

Args:
    action: Action to perform enum ('set', 'get', 'remove', 'search', 'search_decomp'; required)
    address: Address where to set/get/remove the comment (required for set/remove when not using function/line_number)
    address_or_symbol: Address or symbol name (alternative parameter, used for set/get/remove)
    function: Function name or address when setting decompilation line comment or searching decompilation (required for set with line_number, optional for search_decomp)
    function_name_or_address: Function name or address (alternative parameter name)
    line_number: Line number in the decompiled function when action='set' with decompilation (1-based, required for decompilation line comments)
    comment: The comment text to set (required for set)
    comment_type: Type of comment enum ('pre', 'eol', 'post', 'plate', 'repeatable'; default: 'eol')
    start: Start address of the range when action='get' (optional)
    end: End address of the range when action='get' (optional)
    comment_types: Types of comments to retrieve/search (comma-separated: pre,eol,post,plate,repeatable; optional)
    search_text: Text to search for in comments when action='search' (required for search)
    pattern: Regular expression pattern to search for when action='search_decomp' (required for search_decomp)
    case_sensitive: Whether search is case sensitive when action='search' or 'search_decomp' (default: False)
    max_results: Maximum number of results to return when action='search' or 'search_decomp' (default: 100 for search, 50 for search_decomp)
    override_max_functions_limit: Whether to override the maximum function limit for decompiler searches when action='search_decomp' (default: False)

Returns:
    - When action='set': Success or failure message, or JSON with success status for decompilation line comments
    - When action='get': JSON with comments
    - When action='remove': Success or failure message
    - When action='search': JSON with matching comments
    - When action='search_decomp': JSON with search results from decompiled functions

### 12. `analyze-vtables`

Virtual function table analysis tool that replaces: `analyze_vtable`, `find_vtable_callers`, `find_vtables_containing_function`

Analyze vtables, find vtable callers, or find vtables containing a specific function.

Args:
    mode: Analysis mode enum ('analyze', 'callers', 'containing'; required)
    vtable_address: Address of the vtable to analyze when mode='analyze' (required for analyze mode)
    function_address: Address or name of the virtual function when mode='callers' or function to search for when mode='containing' (required for callers/containing modes)
    max_entries: Maximum number of vtable entries to read when mode='analyze' (default: 200)

Returns:
    - When mode='analyze': Vtable structure with function pointers and slot information
    - When mode='callers': List of potential caller sites for the virtual method
    - When mode='containing': JSON with vtables containing the function

### 13. `manage-symbols`

Symbol and label management tool that replaces: `list_classes`, `list_namespaces`, `list_imports`, `list_exports`, `create_label`, `get_symbols`, `get_symbols_count`, `rename_data`

List classes, namespaces, imports, exports, create labels, get symbols, count symbols, or rename data labels.

Args:
    mode: Operation mode enum ('classes', 'namespaces', 'imports', 'exports', 'create_label', 'symbols', 'count', 'rename_data'; required)
    address: Address where to create the label when mode='create_label' or address of data to rename when mode='rename_data' (required for create_label/rename_data)
    label_name: Name for the label when mode='create_label' (required for create_label)
    new_name: New name for the data label when mode='rename_data' (required for rename_data)
    library_filter: Optional library name to filter by when mode='imports' (case-insensitive, optional)
    max_results: Maximum number of imports/exports to return when mode='imports' or 'exports' (default: 500)
    start_index: Starting index for pagination (0-based, default: 0)
    offset: Alternative pagination offset parameter (default: 0, used for backward compatibility)
    limit: Alternative pagination limit parameter (default: 100, used for backward compatibility)
    group_by_library: Whether to group imports by library name when mode='imports' (default: True)
    include_external: Whether to include external symbols when mode='symbols' or 'count' (default: False)
    max_count: Maximum number of symbols to return when mode='symbols' (default: 200)
    filter_default_names: Whether to filter out default Ghidra generated names when mode='symbols' or 'count' (default: True)

Returns:
    - When mode='classes': List of all namespace/class names with pagination
    - When mode='namespaces': List of all non-global namespaces with pagination
    - When mode='imports': JSON with imports list or grouped by library
    - When mode='exports': JSON with exports list
    - When mode='create_label': Success or failure message
    - When mode='symbols': JSON with symbols
    - When mode='count': JSON with symbol count
    - When mode='rename_data': Success or failure message

### 14. `manage-structures`

Structure management tool that replaces: `parse_c_structure`, `validate_c_structure`, `create_structure`, `add_structure_field`, `modify_structure_field`, `modify_structure_from_c`, `get_structure_info`, `list_structures`, `apply_structure`, `delete_structure`, `parse_c_header`

Parse, validate, create, modify, query, list, apply, or delete structures. Also parse entire C header files.

Args:
    action: Action to perform enum ('parse', 'validate', 'create', 'add_field', 'modify_field', 'modify_from_c', 'info', 'list', 'apply', 'delete', 'parse_header'; required)
    c_definition: C-style structure definition when action='parse', 'validate', or 'modify_from_c' (required for parse/validate/modify_from_c)
    header_content: C header file content when action='parse_header' (required for parse_header)
    structure_name: Name of the structure (required for add_field, modify_field, info, apply, delete; optional for list)
    name: Name of the structure when action='create' (required for create)
    size: Initial size when action='create' (0 for auto-sizing, default: 0)
    type: Structure type when action='create' enum ('structure', 'union'; default: 'structure')
    category: Category path (default: '/')
    packed: Whether structure should be packed when action='create' (default: False)
    description: Description of the structure when action='create' (optional)
    field_name: Name of the field when action='add_field' or 'modify_field' (required for add_field, optional for modify_field)
    data_type: Data type when action='add_field' (e.g., 'int', 'char[32]', required for add_field)
    offset: Field offset when action='add_field' or 'modify_field' (optional, omit to append for add_field)
    comment: Field comment when action='add_field' (optional)
    new_data_type: New data type for the field when action='modify_field' (optional)
    new_field_name: New name for the field when action='modify_field' (optional)
    new_comment: New comment for the field when action='modify_field' (optional)
    new_length: New length for the field when action='modify_field' (advanced, optional)
    address_or_symbol: Address or symbol name to apply structure when action='apply' (required for apply)
    clear_existing: Clear existing data when action='apply' (default: True)
    force: Force deletion even if structure is referenced when action='delete' (default: False)
    name_filter: Filter by name (substring match) when action='list' (optional)
    include_built_in: Include built-in types when action='list' (default: False)

Returns:
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

### Structures

### 15. `manage-data-types`

Data type management tool that replaces: `get_data_type_archives`, `get_data_types`, `get_data_type_by_string`, `apply_data_type`

Get data type archives, list data types, get data type by string representation, or apply data types to addresses/symbols.

Args:
    action: Action to perform enum ('archives', 'list', 'by_string', 'apply'; required)
    archive_name: Name of the data type archive when action='list', 'by_string', or 'apply' (required for list, optional for by_string/apply)
    category_path: Path to category to list data types from when action='list' (e.g., '/Structure', use '/' for root, default: '/')
    include_subcategories: Whether to include data types from subcategories when action='list' (default: False)
    start_index: Starting index for pagination when action='list' (0-based, default: 0)
    max_count: Maximum number of data types to return when action='list' (default: 100)
    data_type_string: String representation of the data type when action='by_string' or 'apply' (e.g., 'char**', 'int[10]', required for by_string/apply)
    address_or_symbol: Address or symbol name to apply the data type to when action='apply' (required for apply)

Returns:
    - When action='archives': JSON with data type archives
    - When action='list': JSON with data types
    - When action='by_string': JSON with data type information
    - When action='apply': Success or failure message

### Data Types

### 16. `get-current-context`

Current context retrieval tool that replaces: `get_current_address`, `get_current_function`

Get the address or function currently selected in the Ghidra GUI.

Args:
    mode: Context mode enum ('address', 'function', 'both'; default: 'both')

Returns:
    - When mode='address': The address currently selected by the user
    - When mode='function': The function currently selected by the user
    - When mode='both': JSON with both current address and function

### Current Context

### 17. `manage-function-tags`

Function tag management tool that replaces: `function_tags`

Manage function tags to categorize functions (e.g., 'AI', 'rendering'). Tags can be retrieved, set, added, removed, or listed.

Args:
    function: Function name or address (required for get/set/add/remove modes, not required for list mode)
    mode: Operation mode enum ('get', 'set', 'add', 'remove', 'list'; required)
    tags: Tag names (required for add mode; optional for set/remove modes). Comma-separated format (e.g., "AI,rendering,encryption")

Returns:
    - When mode='get': JSON with tag information for the specified function
    - When mode='set': Success message after replacing all tags on the function
    - When mode='add': Success message after adding tags to the function
    - When mode='remove': Success message after removing tags from the function
    - When mode='list': JSON with all tags in the program

---

## 📊 Tool Consolidation Summary

The 17 consolidated tools above replace all 90 original tools while maintaining 100% feature coverage:

- **Function Analysis**: `get-function`, `list-functions`, `manage-function`
- **Call Analysis**: `get-call-graph`, `get-references`
- **Data Analysis**: `analyze-data-flow`, `search-constants`, `manage-strings`, `inspect-memory`
- **Annotations**: `manage-bookmarks`, `manage-comments`
- **Advanced Analysis**: `analyze-vtables`
- **Symbol Management**: `manage-symbols`
- **Structure Management**: `manage-structures`
- **Type Management**: `manage-data-types`
- **Context & Tags**: `get-current-context`, `manage-function-tags`

Each tool uses mode/action enums and optional parameters to provide the same functionality as multiple original tools, reducing LLM context size and improving tool selection reliability.

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
