# Intelligent Features in ReVa

## Overview

ReVa includes several intelligent features that work automatically to enhance the reverse engineering workflow. These features use heuristics, pattern matching, and program analysis to automatically label, tag, and bookmark program elements. All features are controlled exclusively via environment variables - no tool parameters needed.

## 1. Intelligent Auto-Bookmarking

### What It Does

When addresses are accessed frequently (referenced multiple times), ReVa automatically creates bookmarks to mark them as important. This helps identify critical locations in the binary without manual intervention.

### How It Works

- **Reference Counting**: Collects reference counts for all functions, data, and other referenced addresses in the program
- **Percentile-Based**: Bookmarks only the top 2-5% of addresses by reference count (default: 97th percentile = top 3%)
- **Smart Type Selection**: Chooses appropriate bookmark types based on context:
  - Function entry points → `Analysis` bookmarks
  - Called code locations → `Analysis` bookmarks
  - Writable data → `Warning` bookmarks (potentially important)
  - Read-only data → `Note` bookmarks
  - Other code → `Note` bookmarks

### Configuration

```bash
# Set custom percentile (default: 97.0 = top 3%)
# Range: 95.0-99.0 (bookmarks top 1-5%)
export REVA_AUTO_BOOKMARK_PERCENTILE=98.0
```

### When It Triggers

Auto-bookmarking is triggered automatically when:
- Functions are accessed via `get-function`
- Addresses are accessed via `manage-symbols` (create_label, rename_data)
- Comments are set via `manage-comments`
- Any tool accesses an address that meets the threshold

### Example

```json
// Accessing a function that's called 8 times
{"identifier": "important_function"}

// Automatically creates bookmark (if in top 3% by reference count):
// Type: Analysis
// Category: Auto-Important
// Comment: "Auto-bookmarked: 8 references (threshold: 5)"
```

## 2. Auto-Tagging

### What It Does

Automatically applies function tags based on function analysis, API calls, library imports, and string patterns. When tags are not provided, ReVa automatically analyzes the function and applies appropriate tags.

### How It Works

The tag suggestion system uses multiple strategies:

1. **API Call Analysis**: Detects calls to known APIs and suggests relevant tags
   - `CryptEncrypt` → `["crypto", "security"]`
   - `InternetOpen` → `["network", "http"]`
   - `CreateFile` → `["file_operations", "io"]`

2. **Library Import Analysis**: Analyzes imported libraries
   - `ws2_32.dll` → `["network", "windows_api"]`
   - `crypt32.dll` → `["crypto", "security"]`
   - `libssl.so` → `["crypto", "network"]`

3. **String Pattern Matching**: Examines string references in functions
   - URLs (`https://`) → `["network", "http"]`
   - Security keywords (`password`, `secret`) → `["security", "authentication"]`
   - Crypto terms (`encrypt`, `md5`, `sha256`) → `["crypto", "hashing"]`

4. **Function Characteristic Detection**: Detects operation patterns
   - Crypto operations → `["crypto"]`
   - Network operations → `["network"]`
   - File operations → `["file_operations"]`

### Usage

```json
// Auto-tag (controlled by REVA_AUTO_TAG environment variable)
{
  "mode": "add",
  "function": "encrypt_data"
  // tags not provided - will be auto-tagged if REVA_AUTO_TAG=true
}

// Response includes applied tags:
{
  "success": true,
  "tags": ["crypto", "security"]
}
```

### Configuration

```bash
# Enable/disable auto-tagging (default: true)
export REVA_AUTO_TAG=true
```

## 3. Auto-Labeling

### Function Names

Automatically labels functions based on:
- Nearby string references
- API calls made
- Parameter count and types
- Call patterns (helper functions, entry points)

### Variable Names

Automatically labels variables based on:
- Data type (`char*` → `buffer`, `int` → `value`)
- Pointer types → `ptr`
- Array types → `array`

### Usage

Enabled by default via `REVA_AUTO_LABEL` environment variable in:
- `manage-function` (rename_function, rename_variable)
- `manage-symbols` (create_label, rename_data)

When names are not provided, ReVa automatically assigns appropriate names based on context.

## 4. Auto-Commenting

### Comment Types

Automatically selects appropriate comment types:
- Function entry points → `plate` (function headers)
- Other addresses → `eol` (end-of-line)

### Comment Text

Automatically generates comment text based on:
- Function context (function name, parameter count)
- Address type (function entry, data location)
- Nearby code context

### Usage

Enabled by default via `REVA_AUTO_LABEL` environment variable in `manage-comments`.

When comment type or text is not provided, ReVa automatically assigns appropriate values based on context.

## Configuration Summary

All intelligent features are controlled exclusively via environment variables:

```bash
# Enable/disable auto-labeling (names, comments) (default: true)
export REVA_AUTO_LABEL=true

# Enable/disable auto-tagging (default: true)
export REVA_AUTO_TAG=true

# Auto-bookmark percentile (default: 97.0 = top 3%, range: 95.0-99.0)
export REVA_AUTO_BOOKMARK_PERCENTILE=98.0
```

**Note**: These features have no tool parameters - they are controlled entirely via environment variables to simplify the API and avoid confusing AI agents.

## Best Practices

1. **Let Auto-Labeling Help**: Keep `REVA_AUTO_LABEL=true` (default) to get automatic names, then refine manually
2. **Adjust Bookmark Threshold**: For large binaries, increase threshold to avoid bookmark spam
3. **Review Auto-Bookmarks**: Check auto-bookmarked addresses to ensure they're actually important
4. **Refine Auto-Tags**: Auto-tagged functions are a starting point - add more specific tags as needed
5. **Use Tags Consistently**: Establish a tag naming convention and stick to it
6. **Environment Variable Control**: All features are controlled via environment variables - no need to pass parameters in tool calls

## Technical Details

### Bookmarking Algorithm

1. Count references to address using `ReferenceManager.getReferencesTo()`
2. Check if count exceeds threshold
3. Determine bookmark type based on address context and reference types
4. Create bookmark in transaction if threshold exceeded
5. Update existing bookmarks if address already bookmarked

### Tag Auto-Labeling Algorithm

1. Analyze function's API calls
2. Check imported libraries
3. Examine string references for patterns
4. Detect operation patterns (crypto, network, file I/O)
5. Score tags by confidence (0.0-1.0)
6. Return top suggestions sorted by confidence

### Performance

- **Bookmarking**: Minimal overhead - only checks when addresses are accessed
- **Tag Suggestions**: Analyzes function on-demand, cached per function
- **Name Suggestions**: Fast heuristics-based analysis

## Summary

ReVa's intelligent features work together to:
- **Automatically identify important addresses** (auto-bookmarking)
- **Automatically apply appropriate tags** based on function analysis
- **Automatically assign meaningful names** for functions and variables
- **Automatically set comment types and text** based on context

These features are enabled by default and controlled exclusively via environment variables (no tool parameters). They're designed to enhance productivity without getting in the way - automatic labeling happens when values are not provided, but explicit values always take precedence.
