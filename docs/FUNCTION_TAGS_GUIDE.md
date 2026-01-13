# Function Tags: Comprehensive Guide

## Overview

Function tags are a **categorization system** for organizing functions in Ghidra programs. They allow you to group functions by purpose, domain, or any other meaningful classification scheme. Tags are particularly powerful for large codebases where manual organization would be impractical.

## Who Created Tags and Why?

### Origin
Function tags are a **native Ghidra feature** (not specific to ReVa). They were introduced in Ghidra to address the challenge of organizing and navigating large reverse engineering projects.

### Purpose
Tags solve several critical problems in reverse engineering:

1. **Organization at Scale**: In binaries with thousands of functions, finding related functionality is difficult. Tags provide a lightweight categorization system.

2. **Workflow Management**: Tags help track analysis progress:
   - Tag functions as "analyzed" vs "needs_review"
   - Mark functions by domain: "crypto", "network", "file_operations"
   - Identify functions by importance: "critical", "helper", "unused"

3. **Collaboration**: Multiple analysts can use consistent tag schemes to coordinate work.

4. **Querying and Filtering**: Tags enable powerful queries:
   - "Show me all crypto functions"
   - "What functions still need analysis?"
   - "Find all network-related functions"

## Best Use Cases

### 1. **Domain-Based Organization** (Most Common)
Organize functions by what they do:

```json
// Tag functions by domain
{"mode": "add", "function": "encrypt_data", "tags": ["crypto", "security"]}
{"mode": "add", "function": "send_packet", "tags": ["network", "communication"]}
{"mode": "add", "function": "read_config", "tags": ["file_operations", "io"]}
```

**Benefits**:
- Quickly find all crypto-related code
- Understand system architecture at a glance
- Navigate large codebases efficiently

### 2. **Analysis Progress Tracking**
Track which functions have been analyzed:

```json
// Mark analysis status
{"mode": "add", "function": "main", "tags": ["analyzed", "documented"]}
{"mode": "add", "function": "helper_func", "tags": ["needs_review"]}
{"mode": "add", "function": "unknown_func", "tags": ["unanalyzed"]}
```

**Benefits**:
- Know what's been covered
- Identify gaps in analysis
- Track progress over time

### 3. **Security Analysis**
Tag functions by security relevance:

```json
{"mode": "add", "function": "validate_input", "tags": ["security", "input_validation"]}
{"mode": "add", "function": "handle_auth", "tags": ["security", "authentication"]}
{"mode": "add", "function": "decrypt_key", "tags": ["security", "crypto", "critical"]}
```

**Benefits**:
- Focus security review on tagged functions
- Identify security-critical code paths
- Track security-related analysis

### 4. **Architecture Understanding**
Tag by architectural role:

```json
{"mode": "add", "function": "init_system", "tags": ["initialization", "startup"]}
{"mode": "add", "function": "cleanup_resources", "tags": ["cleanup", "shutdown"]}
{"mode": "add", "function": "event_handler", "tags": ["event_loop", "async"]}
```

**Benefits**:
- Understand system flow
- Identify architectural patterns
- Map system components

### 5. **CTF and Challenge Analysis**
Tag by challenge category:

```json
{"mode": "add", "function": "check_flag", "tags": ["ctf", "flag_validation"]}
{"mode": "add", "function": "decrypt_challenge", "tags": ["ctf", "crypto", "challenge"]}
```

**Benefits**:
- Organize CTF solutions
- Track solved challenges
- Share analysis with team

## Auto-Tagging

ReVa now includes **intelligent auto-tagging** that automatically analyzes functions and applies appropriate tags based on:

1. **API Calls**: Functions calling `CryptEncrypt` → `["crypto", "security"]`
2. **Library Imports**: Functions from `ws2_32.dll` → `["network", "windows_api"]`
3. **String Patterns**: Functions referencing "https://" → `["network", "http"]`
4. **Function Characteristics**: Functions with crypto operations → `["crypto"]`

### How It Works

When you use `manage-function-tags` with `REVA_AUTO_TAG=true` (default), ReVa automatically:

1. Analyzes the function's API calls
2. Checks imported libraries
3. Examines string references
4. Detects operation patterns (crypto, network, file I/O)
5. Suggests relevant tags with confidence scores

### Example

```json
// Without tags - auto-tag will analyze and apply
{
  "programPath": "/program.exe",
  "mode": "add",
  "function": "encrypt_user_data"
  // tags not provided - will be auto-tagged if REVA_AUTO_TAG=true
}

// Response includes applied tags:
{
  "success": true,
  "function": "encrypt_user_data",
  "tags": ["crypto", "security", "file_operations"]
}
```

### Configuration

```bash
# Enable/disable auto-tagging (default: true)
export REVA_AUTO_TAG=true
```

## Tag Patterns and Heuristics

### API-Based Tagging
ReVa recognizes common APIs and suggests tags:

| API | Suggested Tags |
|-----|----------------|
| `CreateFile`, `ReadFile`, `WriteFile` | `file_operations`, `io` |
| `CryptEncrypt`, `CryptDecrypt` | `crypto`, `security` |
| `InternetOpen`, `HttpSendRequest` | `network`, `http` |
| `RegOpenKey`, `RegQueryValue` | `registry`, `windows_api` |
| `malloc`, `free` | `memory_operations` |

### Library-Based Tagging
Tags are suggested based on imported libraries:

| Library | Suggested Tags |
|---------|----------------|
| `kernel32.dll` | `windows_api`, `system` |
| `ws2_32.dll` | `network`, `windows_api` |
| `crypt32.dll` | `crypto`, `security` |
| `libssl.so` | `crypto`, `network` |
| `libc.so` | `c_runtime`, `standard_library` |

### String Pattern Tagging
Functions referencing certain strings get tagged:

| Pattern | Suggested Tags |
|---------|----------------|
| `https://`, `http://` | `network`, `http` |
| `password`, `secret`, `key` | `security`, `authentication` |
| `encrypt`, `decrypt` | `crypto` |
| `md5`, `sha256`, `aes` | `crypto`, `hashing` |
| File extensions (`.exe`, `.dll`) | `file_operations` |

## Tag Operations

### Get Tags
```json
{"mode": "get", "function": "main"}
// Returns: {"tags": ["analyzed", "entry_point"]}
```

### Set Tags (Replace All)
```json
{"mode": "set", "function": "main", "tags": ["analyzed", "entry_point", "critical"]}
// Replaces all existing tags with the new list
```

### Add Tags
```json
{"mode": "add", "function": "main", "tags": ["documented"]}
// Adds to existing tags (doesn't remove existing ones)
```

### Remove Tags
```json
{"mode": "remove", "function": "main", "tags": ["needs_review"]}
// Removes specified tags
```

### List All Tags
```json
{"mode": "list"}
// Returns all tags in program with usage counts:
// {"tags": [{"name": "crypto", "count": 15}, {"name": "network", "count": 8}]}
```

## Querying by Tags

Use `get-functions` with tag filters:

```json
// Find all crypto functions
{"filterByTag": "crypto"}

// Find untagged functions (need categorization)
{"untagged": true}
```

## Best Practices

1. **Use Consistent Naming**: Use lowercase with underscores: `file_operations` not `FileOperations`

2. **Hierarchical Tags**: Use multiple tags for specificity:
   - `["crypto", "encryption"]` - more specific than just `["crypto"]`
   - `["network", "http", "client"]` - describes both domain and role

3. **Progress Tags**: Use tags to track analysis:
   - `analyzed`, `needs_review`, `documented`, `unanalyzed`

4. **Domain Tags**: Organize by functional domain:
   - `crypto`, `network`, `file_operations`, `ui`, `database`

5. **Importance Tags**: Mark critical functions:
   - `critical`, `helper`, `unused`, `entry_point`

6. **Let Auto-Tagging Help**: Enable `REVA_AUTO_TAG=true` to get automatic tags, then refine manually

## Integration with Other Tools

Tags are included in all function listings:

- `get-functions` includes tags in each function's metadata
- `get-function` includes tags in function info
- Function similarity search respects tags
- Tags are searchable and filterable

## Summary

Function tags are a **powerful organizational tool** that:
- Help navigate large codebases
- Track analysis progress
- Enable domain-based organization
- Support collaborative analysis
- Work seamlessly with auto-suggestions

The best use case is **domain-based organization** combined with **analysis progress tracking**, especially in large binaries where manual navigation is impractical.
