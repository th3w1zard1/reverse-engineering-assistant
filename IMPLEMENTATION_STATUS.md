# Implementation Status: Comprehensive Function Analysis

## Current Problem

AI agents are making hundreds/thousands of tool calls when tasked with bulk function analysis:
- Repeated `list-functions` calls with pagination (100+ calls for 13,876 functions)
- Individual `get-function` calls for each function (13,876+ calls)
- Individual `get-references` calls
- Result: Only 20 functions documented in 1 hour instead of all 13,876

## What Needs to Be Implemented

### 1. Comprehensive Mode in `list-functions` Tool

**Location:** `src/main/java/reva/tools/functions/FunctionToolProvider.java`

**Status:** ⚠️ **NOT YET IMPLEMENTED** - Only documented

**Required Implementation:**
- Add `'comprehensive'` to mode enum
- Handle `programPath` as string OR array (multi-program support)
- Collect ALL functions internally (no pagination limits)
- Return full function details: name, address, signature, parameters, return type, call counts, reference counts
- Optional: include decompiled code (can be slow)
- Optional: run signature scanning before collection
- Optional: include undefined function candidates

**Key Requirements:**
- Must return ALL functions in one response (no pagination)
- Must support multiple programs in one call
- Must include signature scanning integration
- Must be performant for 10,000+ functions

### 2. Multi-Program Support

**Status:** ⚠️ **PARTIALLY DOCUMENTED** - Needs implementation

**Required:**
- Accept `programPath` as array: `["/swkotor.exe", "/swkotor2.exe", "/swkotor2_aspyr.exe"]`
- Process all programs and return results grouped by program
- Signature scanning should work across all programs

### 3. Signature Scanning Integration

**Status:** ❓ **UNKNOWN** - User mentioned it was "already implemented" but needs verification

**Required:**
- Integrate Ghidra's signature scanning (`FunctionSignatureDB`, `ApplyFunctionSignaturesScript`)
- Run before function collection to discover undefined functions
- Should work across multiple programs
- Should be optional (controlled by `run_signature_scanning` parameter)

## Implementation Priority

### Phase 1: Core Comprehensive Mode (CRITICAL)
1. Add comprehensive mode handler
2. Collect all functions (no pagination)
3. Return full function details
4. Single program support

### Phase 2: Multi-Program Support (HIGH)
1. Accept array for `programPath`
2. Process multiple programs
3. Group results by program

### Phase 3: Signature Scanning (MEDIUM)
1. Integrate signature scanning
2. Run before function collection
3. Include undefined functions in results

### Phase 4: Performance Optimization (LOW)
1. Optimize for 10,000+ functions
2. Add progress reporting for long operations
3. Cache decompilation results

## Expected Behavior After Implementation

**Before (Current - Inefficient):**
```
Task: "Fully document all functions in swkotor.exe, swkotor2.exe, swkotor2_aspyr.exe"
Agent behavior:
1. list-functions (mode='all', max_count=100, start_index=0) - Call 1
2. list-functions (mode='all', max_count=100, start_index=100) - Call 2
3. ... (repeat 140+ times for pagination)
4. get-function (identifier="function1") - Call 141
5. get-function (identifier="function2") - Call 142
6. ... (repeat 13,876+ times)
Result: 14,000+ tool calls, 1 hour = 20 functions documented
```

**After (With Comprehensive Mode - Efficient):**
```
Task: "Fully document all functions in swkotor.exe, swkotor2.exe, swkotor2_aspyr.exe"
Agent behavior:
1. list-functions (mode='comprehensive', programPath=["/swkotor.exe", "/swkotor2.exe", "/swkotor2_aspyr.exe"], run_signature_scanning=true) - Call 1
Result: 1 tool call, returns ALL 13,876+ functions with full details, ready for batch processing
```

## Testing Requirements

1. **Single Program Test:**
   - Call comprehensive mode on single program
   - Verify all functions returned (no pagination)
   - Verify full details included

2. **Multi-Program Test:**
   - Call comprehensive mode with array of programs
   - Verify results grouped by program
   - Verify all programs processed

3. **Signature Scanning Test:**
   - Enable signature scanning
   - Verify undefined functions discovered
   - Verify functions created from signatures

4. **Performance Test:**
   - Test with 10,000+ functions
   - Verify reasonable response time
   - Verify no memory issues

5. **Integration Test:**
   - Full workflow: comprehensive mode → batch manage-function → batch manage-comments
   - Verify all functions can be processed efficiently

## Code Location

Based on documentation, the implementation should be in:
- `src/main/java/reva/tools/functions/FunctionToolProvider.java`

However, this file is not currently in the repository. It may be:
- In a different branch
- Not yet committed
- In a different location

## Next Steps

1. **Locate the actual source code** for FunctionToolProvider
2. **Implement comprehensive mode** following the guide in `COMPREHENSIVE_FUNCTION_ANALYSIS.md`
3. **Test with real programs** (swkotor.exe, swkotor2.exe, swkotor2_aspyr.exe)
4. **Verify signature scanning** integration
5. **Update documentation** with actual implementation details
