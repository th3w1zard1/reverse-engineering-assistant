# Import/Export Tools Package - CLAUDE.md

This package provides tools for analyzing imported and exported symbols in binaries.

**NOTE: These tools are DISABLED.** The functionality has been merged into the `manage-symbols` tool in the SymbolToolProvider with modes 'imports' and 'exports'. The ImportExportToolProvider is kept for upstream repository compatibility but all tools are commented out.

## Disabled Tools

### `list-imports` (DISABLED)
**Use `manage-symbols` with mode='imports' instead**

Lists all imported functions from external libraries.

**Parameters:**
- `programPath` (string, required): Path to the program in the Ghidra project
- `libraryFilter` (string, optional): Filter by library name (case-insensitive partial match)
- `startIndex` (int, optional): Pagination start index (default: 0)
- `maxResults` (int, optional): Maximum number of results to return (default: 500, max: 2000)

**Response:**
```json
{
  "success": true,
  "programPath": "/path/to/program.exe",
  "importCount": 42,
  "libraryCount": 5,
  "imports": [
    {
      "name": "printf",
      "library": "msvcrt.dll",
      "address": "0x00401000",
      "originalName": "printf",
      "signature": "int printf(char *format, ...)"
    }
  ],
  "libraries": [
    {
      "name": "msvcrt.dll",
      "importCount": 25,
      "imports": [...]
    }
  ]
}
```

### `list-exports` (DISABLED)
**Use `manage-symbols` with mode='exports' instead**

Lists all exported symbols from the binary.

**Parameters:**
- `programPath` (string, required): Path to the program in the Ghidra project
- `startIndex` (int, optional): Pagination start index (default: 0)
- `maxResults` (int, optional): Maximum number of results to return (default: 500, max: 2000)

**Response:**
```json
{
  "success": true,
  "programPath": "/path/to/program.exe",
  "exportCount": 15,
  "exports": [
    {
      "name": "exported_function",
      "address": "0x00405000",
      "symbolType": "FUNCTION",
      "isFunction": true,
      "signature": "int exported_function(int param)"
    }
  ]
}
```

### `get-import-details` (DISABLED)
**Use `manage-symbols` with mode='imports' instead**

Get detailed information about a specific imported function.

**Parameters:**
- `programPath` (string, required): Path to the program in the Ghidra project
- `importName` (string, required): Name of the imported function
- `libraryName` (string, optional): Library name to filter results

**Response:**
```json
{
  "success": true,
  "programPath": "/path/to/program.exe",
  "import": {
    "name": "printf",
    "library": "msvcrt.dll",
    "address": "0x00401000",
    "originalName": "printf",
    "ordinal": null,
    "signature": "int printf(char *format, ...)",
    "thunkChain": [
      {
        "name": "printf",
        "address": "0x00401000",
        "isThunk": false,
        "isExternal": true,
        "library": "msvcrt.dll",
        "originalName": "printf"
      }
    ]
  }
}
```

### `get-export-details` (DISABLED)
**Use `manage-symbols` with mode='exports' instead**

Get detailed information about a specific exported symbol.

**Parameters:**
- `programPath` (string, required): Path to the program in the Ghidra project
- `exportName` (string, required): Name of the exported symbol

**Response:**
```json
{
  "success": true,
  "programPath": "/path/to/program.exe",
  "export": {
    "name": "exported_function",
    "address": "0x00405000",
    "symbolType": "FUNCTION",
    "isFunction": true,
    "signature": "int exported_function(int param)"
  }
}
```

## Migration Guide

All import/export functionality has been consolidated into the `manage-symbols` tool in the SymbolToolProvider:

- `list-imports` → `manage-symbols` with `mode='imports'`
- `list-exports` → `manage-symbols` with `mode='exports'`
- `get-import-details` → `manage-symbols` with `mode='imports'` and `filter`
- `get-export-details` → `manage-symbols` with `mode='exports'` and `filter`

The new unified interface provides better consistency and additional filtering options.