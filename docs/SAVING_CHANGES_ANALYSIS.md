# Analysis: How Changes Are Saved in ReVa

## Executive Summary

**The Problem:** Changes made via tools like `set-comment` and `rename-function` are **NOT automatically saved to disk**. They only exist in memory until you explicitly call `checkin-program` or `program.save()`. When you call `open-project` again, it may reload programs from disk, losing unsaved in-memory changes.

## How Changes Currently Work

### 1. `set-comment` (CommentToolProvider.java)

```102:114:reverse-engineering-assistant/src/main/java/reva/tools/comments/CommentToolProvider.java
            try {
                int transactionId = program.startTransaction("Set Comment");
                try {
                    Listing listing = program.getListing();
                    listing.setComment(address, commentType, comment);

                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("address", address.toString());
                    result.put("commentType", commentTypeStr);
                    result.put("comment", comment);

                    program.endTransaction(transactionId, true);
                    return createJsonResult(result);
```

**Key Finding:** 
- ✅ Uses transactions correctly (`startTransaction` → `endTransaction(transactionId, true)`)
- ❌ **Does NOT call `program.save()`** - changes are only in memory
- ❌ Changes will be lost if program is closed/reopened without saving

### 2. `rename-function` / `set-function-prototype` (FunctionToolProvider.java)

```1031:1125:reverse-engineering-assistant/src/main/java/reva/tools/functions/FunctionToolProvider.java
                int txId = program.startTransaction("Set Function Prototype");
                try {
                    Function function = existingFunction;

                    // Create function if it doesn't exist and creation is allowed
                    if (function == null) {
                        if (!createIfNotExists) {
                            return createErrorResult("Function does not exist at " +
                                AddressUtil.formatAddress(address) + " and createIfNotExists is false");
                        }

                        // Create a new function with minimal body (just the entry point)
                        AddressSet body = new AddressSet(address, address);
                        function = functionManager.createFunction(
                            functionDef.getName(), address, body, SourceType.USER_DEFINED);

                        if (function == null) {
                            return createErrorResult("Failed to create function at " +
                                AddressUtil.formatAddress(address));
                        }
                    }

                    // Check if we need to enable custom storage to modify auto-parameters
                    // Only enable it if an auto-parameter's type is actually being changed
                    boolean needsCustomStorage = needsCustomStorageForSignature(function, functionDef);
                    boolean wasUsingCustomStorage = function.hasCustomVariableStorage();

                    if (needsCustomStorage && !wasUsingCustomStorage) {
                        // Enable custom storage to allow modifying auto-parameters like 'this'
                        function.setCustomVariableStorage(true);
                        logInfo("Enabled custom storage for function " + function.getName() +
                                " to allow modifying auto-parameters (e.g., 'this' in __thiscall)");
                    }

                    // Update function name if it's different
                    if (!function.getName().equals(functionDef.getName())) {
                        function.setName(functionDef.getName(), SourceType.USER_DEFINED);
                    }

                    // Convert ParameterDefinitions to Variables (Parameters extend Variable)
                    // If using custom storage, preserve existing parameter storage where possible
                    List<Variable> parameters = new ArrayList<>();
                    ParameterDefinition[] paramDefs = functionDef.getArguments();
                    Parameter[] existingParams = function.getParameters();

                    for (int i = 0; i < paramDefs.length; i++) {
                        ParameterDefinition paramDef = paramDefs[i];

                        // If using custom storage and this parameter index exists, preserve its storage
                        if (function.hasCustomVariableStorage() && i < existingParams.length) {
                            // Preserve the existing parameter's storage when updating its type
                            parameters.add(new ParameterImpl(
                                paramDef.getName(),
                                paramDef.getDataType(),
                                existingParams[i].getVariableStorage(),
                                program));
                        } else {
                            // Create parameter without explicit storage (will be auto-assigned)
                            parameters.add(new ParameterImpl(
                                paramDef.getName(),
                                paramDef.getDataType(),
                                program));
                        }
                    }

                    // Update the function signature
                    // First update return type separately
                    function.setReturnType(functionDef.getReturnType(), SourceType.USER_DEFINED);

                    // Then update parameters
                    // Use appropriate update type based on whether we're using custom storage
                    Function.FunctionUpdateType updateType = function.hasCustomVariableStorage()
                        ? Function.FunctionUpdateType.CUSTOM_STORAGE
                        : Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;

                    function.replaceParameters(parameters, updateType, true, SourceType.USER_DEFINED);

                    // Set varargs if needed
                    if (functionDef.hasVarArgs() != function.hasVarArgs()) {
                        function.setVarArgs(functionDef.hasVarArgs());
                    }

                    program.endTransaction(txId, true);

                    // Return updated function information
                    Map<String, Object> result = new HashMap<>();
                    result.put("success", true);
                    result.put("created", existingFunction == null);
                    result.put("function", createFunctionInfo(function, null));
                    result.put("address", AddressUtil.formatAddress(address));
                    result.put("parsedSignature", functionDef.toString());
                    result.put("customStorageEnabled", needsCustomStorage && !wasUsingCustomStorage);
                    result.put("usingCustomStorage", function.hasCustomVariableStorage());

                    return createJsonResult(result);
```

**Key Finding:**
- ✅ Uses transactions correctly
- ❌ **Does NOT call `program.save()`** - changes are only in memory
- ❌ Changes will be lost if program is closed/reopened without saving

### 3. `open-project` (ProjectToolProvider.java)

```1131:1167:reverse-engineering-assistant/src/main/java/reva/tools/project/ProjectToolProvider.java
                if (shouldOpenAllPrograms) {
                    for (DomainFile domainFile : allPrograms) {
                        String programPath = domainFile.getPathname();
                        try {
                            // Use RevaProgramManager to open the program - this caches it for future access
                            // This will automatically handle any program upgrades needed
                            Program program = RevaProgramManager.getProgramByPath(programPath);
                            if (program != null && !program.isClosed()) {
                                openedPrograms.add(programPath);
                                String logMsg = "Opened program: " + programPath;
                                Msg.info(this, logMsg);
                                logCollector.addLog("INFO", logMsg);
                                
                                // If program was upgraded, save it immediately
                                // Check if the domain file has unsaved changes
                                if (domainFile.isChanged()) {
                                    try {
                                        domainFile.save(null, TaskMonitor.DUMMY);
                                        String saveProgramMsg = "Saved upgraded program: " + programPath;
                                        Msg.info(this, saveProgramMsg);
                                        logCollector.addLog("INFO", saveProgramMsg);
                                    } catch (Exception saveProgramException) {
                                        String saveProgramWarnMsg = "Warning: Failed to save upgraded program " + programPath + ": " + saveProgramException.getMessage();
                                        Msg.warn(this, saveProgramWarnMsg);
                                        logCollector.addLog("WARN", saveProgramWarnMsg);
                                    }
                                }
                            } else {
                                failedPrograms.add(programPath + " (returned null or closed)");
                            }
                        } catch (Exception e) {
                            failedPrograms.add(programPath + " (" + e.getMessage() + ")");
                            String logMsg = "Failed to open program " + programPath + ": " + e.getMessage();
                            Msg.warn(this, logMsg);
                            logCollector.addLog("WARN", logMsg);
                        }
                    }
```

**Key Finding:**
- ✅ Opens programs and caches them via `RevaProgramManager.getProgramByPath()`
- ✅ Saves programs if they were upgraded (`domainFile.isChanged()`)
- ❌ **Does NOT check for or save programs with unsaved modifications from previous sessions**
- ❌ If you made changes (comments, renames) and didn't save, `open-project` will reload from disk, losing those changes

### 4. `checkin-program` - The Only Tool That Saves

```332:341:reverse-engineering-assistant/src/main/java/reva/tools/project/ProjectToolProvider.java
                // Save program first (required before version control operations)
                // Skip save for read-only programs (common in test environments)
                if (!domainFile.isReadOnly()) {
                    try {
                        program.save(message, TaskMonitor.DUMMY);
                        program.flushEvents();  // Ensure SAVED event is processed
                    } catch (java.io.IOException e) {
                        return createErrorResult("Failed to save program: " + e.getMessage());
                    }
                }
```

**Key Finding:**
- ✅ **This is the ONLY tool that explicitly saves programs**
- ✅ Calls `program.save(message, TaskMonitor.DUMMY)` before version control operations
- ⚠️ But you must remember to call it after making changes, or changes are lost

## The Root Cause

**Ghidra's transaction model:**
- `startTransaction()` / `endTransaction()` only commit changes to **in-memory program state**
- Changes are **NOT automatically persisted to disk**
- You must explicitly call `program.save()` to write changes to the project database

**ReVa's current behavior:**
- Most modification tools (set-comment, rename-function, etc.) only use transactions
- They don't call `program.save()` automatically
- Changes exist only in memory until `checkin-program` is called
- When `open-project` is called again, it may reload from disk, losing unsaved changes

## Solutions

### Option 1: Auto-Save After Modifications (Recommended)

Modify tools to automatically save after successful transactions:

```java
// In CommentToolProvider.java, after endTransaction:
program.endTransaction(transactionId, true);

// Add auto-save:
if (!program.getDomainFile().isReadOnly()) {
    try {
        program.save("Auto-save: Set comment", TaskMonitor.DUMMY);
    } catch (Exception e) {
        logError("Failed to auto-save after set-comment", e);
        // Don't fail the operation, just log the warning
    }
}
```

**Pros:**
- Changes persist immediately
- No need to remember to call `checkin-program`
- Matches user expectations

**Cons:**
- May be slower (disk I/O on every change)
- Could cause issues with version control if program is checked in
- May interfere with batch operations

### Option 2: Check for Unsaved Changes in `open-project`

Modify `open-project` to detect and preserve unsaved changes:

```java
// Before opening a program, check if it's already open with unsaved changes
Program existingProgram = RevaProgramManager.getProgramByPath(programPath);
if (existingProgram != null && !existingProgram.isClosed()) {
    DomainFile domainFile = existingProgram.getDomainFile();
    if (domainFile.isChanged()) {
        // Program has unsaved changes - save them first
        try {
            domainFile.save(null, TaskMonitor.DUMMY);
            Msg.info(this, "Saved unsaved changes for: " + programPath);
        } catch (Exception e) {
            Msg.warn(this, "Failed to save unsaved changes: " + e.getMessage());
        }
    }
}
```

**Pros:**
- Preserves changes when reopening projects
- Less intrusive than auto-save on every change

**Cons:**
- Still requires explicit save (just happens automatically on reopen)
- Doesn't help if program is closed before `open-project` is called

### Option 3: Add `save-program` Tool

Create a dedicated tool for saving programs:

```java
registerSaveProgramTool() {
    // Tool that explicitly saves a program
    // Can be called after batch operations
}
```

**Pros:**
- Explicit control over when to save
- Good for batch operations

**Cons:**
- Still requires remembering to call it
- Doesn't solve the "lost changes" problem

### Option 4: Hybrid Approach (Best)

1. **Auto-save for simple operations** (set-comment, rename-variable) - Option 1
2. **Check for unsaved changes in open-project** - Option 2
3. **Add save-program tool** - Option 3
4. **Add `open-program` tool** that imports and saves a program to the project

## Missing Feature: `open-program` Tool

Currently, there's no tool to:
- Import a binary file into the project
- Open it in memory
- Save it to the project

The `import-file` tool imports but doesn't necessarily open programs. You need:
1. `import-file` to add to project
2. Then access via `programPath` to open it

A combined `open-program` tool would:
```java
registerOpenProgramTool() {
    // 1. Check if program already exists in project
    // 2. If not, import it
    // 3. Open it in memory (cache it)
    // 4. Save it to project
    // 5. Return programPath for use in other tools
}
```

## Recommendations

1. **Immediate Fix:** Add auto-save to `set-comment` and other high-frequency modification tools
2. **Short-term:** Add unsaved changes check in `open-project`
3. **Medium-term:** Add `save-program` tool for explicit control
4. **Long-term:** Add `open-program` tool that combines import + open + save

## Testing

The test file `test_e2e_workflow.py` shows the expected workflow:
1. Import binary
2. Open program (auto-checkout)
3. Make changes
4. **Save changes** (via `checkin-program`)
5. Reopen program
6. Verify changes persist

This confirms that **explicit saving is required** for changes to persist.

