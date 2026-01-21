# CLAUDE.md - Suggestions Tool Provider

This file provides guidance to Claude Code when working with the suggestions tool provider in ReVa.

## Package Overview

The `reva.tools.suggestions` package provides context-aware suggestions for reverse engineering analysis. It helps users discover appropriate names, comments, data types, and function tags based on program context and patterns.

## Available Tools

### `suggest`

Get context-aware suggestions for various reverse engineering tasks.

**Parameters:**
- `programPath` (string, required): Path to the program in the Ghidra project
- `suggestionType` (string, required): Type of suggestion to get. One of:
  - `comment_type` - Suggest appropriate comment type (e.g., "plate", "pre", "post")
  - `comment_text` - Suggest comment text content
  - `function_name` - Suggest better function names
  - `function_tags` - Suggest appropriate function tags
  - `variable_name` - Suggest variable names based on data type
  - `data_type` - Suggest appropriate data types for addresses
- `address` (string, optional): Address or symbol name (required for `comment_type`, `comment_text`, `data_type`)
- `function` (string, optional): Function name or address (required for `function_name`, `function_tags`, `variable_name`)
- `dataType` (string, optional): Data type string (required for `variable_name` suggestion)
- `variableAddress` (string, optional): Address of variable/data (required for `data_type` suggestion)

**Response Format:**
All responses include:
- `suggestionType`: The type of suggestion requested
- `programPath`: The program path
- Suggestion-specific fields based on the type

**Examples:**

#### Comment Type Suggestion
```json
{
  "suggestionType": "comment_type",
  "address": "0x00401000",
  "suggestion": {
    "suggestedType": "plate",
    "confidence": 0.85,
    "reasoning": "This appears to be a function prologue with standard stack setup"
  }
}
```

#### Comment Text Suggestion
```json
{
  "suggestionType": "comment_text",
  "address": "0x00401000",
  "suggestion": {
    "suggestedText": "Standard function prologue - save registers and allocate stack space",
    "confidence": 0.90,
    "reasoning": "Pattern matches typical x86 function prologue sequence"
  }
}
```

#### Function Name Suggestion
```json
{
  "suggestionType": "function_name",
  "function": "sub_401000",
  "address": "0x00401000",
  "suggestions": [
    {
      "name": "initialize_globals",
      "confidence": 0.92,
      "reasoning": "Function accesses multiple global variables and appears to initialize them"
    },
    {
      "name": "setup_environment",
      "confidence": 0.78,
      "reasoning": "Function performs environment setup operations"
    }
  ]
}
```

#### Function Tags Suggestion
```json
{
  "suggestionType": "function_tags",
  "function": "sub_401000",
  "address": "0x00401000",
  "currentTags": ["LIBRARY"],
  "suggestions": [
    {
      "tag": "INIT",
      "confidence": 0.88,
      "reasoning": "Function performs initialization of global data structures"
    },
    {
      "tag": "EXPORTED",
      "confidence": 0.65,
      "reasoning": "Function is referenced from external modules"
    }
  ]
}
```

#### Variable Name Suggestion
```json
{
  "suggestionType": "variable_name",
  "function": "main",
  "dataType": "int*",
  "suggestion": {
    "suggestedName": "result_ptr",
    "confidence": 0.85,
    "reasoning": "Pointer to integer, likely stores a result value"
  }
}
```

#### Data Type Suggestion
```json
{
  "suggestionType": "data_type",
  "address": "0x00402000",
  "suggestion": {
    "suggestedType": "char*",
    "confidence": 0.95,
    "reasoning": "Address contains string-like data with null termination"
  }
}
```

## Implementation Notes

- Suggestions are based on static analysis of the program
- Confidence scores indicate the reliability of suggestions
- Multiple suggestions may be provided when appropriate
- Context-aware analysis considers surrounding code patterns
- Suggestions can help improve code readability and analysis accuracy

## Usage Patterns

1. **Function Analysis**: Use `function_name` and `function_tags` suggestions when analyzing unidentified functions
2. **Data Analysis**: Use `data_type` suggestions when identifying data structures
3. **Comment Enhancement**: Use `comment_type` and `comment_text` for documentation improvements
4. **Variable Naming**: Use `variable_name` suggestions when creating meaningful variable names

## Suggestion Types

### Functions
- Analyzes undefined code for function prologue patterns
- Suggests function creation at addresses with call references but no function definition
- Considers instruction patterns, stack usage, and cross-references

### Variables
- Analyzes local variable usage patterns
- Suggests meaningful names based on context (loop counters, array indices, etc.)
- Considers data flow and variable relationships

### Comments
- Suggests comments for complex code sections
- Identifies patterns that may indicate specific algorithms or behaviors
- Provides documentation suggestions for better analysis

### Tags
- Suggests function categorization tags
- Analyzes function behavior to suggest appropriate tags (e.g., "crypto", "network", "file_io")
- Helps organize functions by purpose or behavior

### Data Types
- Suggests structure definitions for complex data layouts
- Analyzes memory access patterns to infer data structures
- Provides recommendations for improving data type analysis

## Implementation Notes

- Suggestions are generated based on Ghidra's analysis results and heuristics
- Confidence scores indicate the reliability of each suggestion
- The tool analyzes the current program state and provides actionable recommendations
- Suggestions can be applied using other ReVa tools (function creation, variable renaming, etc.)

## Integration with Other Tools

Suggestions work well with other ReVa tools:

- Use `functions-create` to apply function creation suggestions
- Use `decompiler-rename-variable` to apply variable naming suggestions
- Use `comments-set` to apply comment suggestions
- Use `functions-set-tags` to apply tag suggestions

## Error Handling

The tool handles common analysis scenarios gracefully:
- Returns empty suggestions array for programs with minimal analysis
- Provides appropriate error messages for invalid parameters
- Handles cases where analysis is incomplete or unavailable
