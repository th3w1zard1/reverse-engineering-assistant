# Ghidra Project Locking Explained

## Overview

Ghidra projects use **file-based locking** to prevent multiple processes from opening the same project simultaneously. This is a **built-in Ghidra feature**, not something ReVa controls.

## How Locking Works

### Lock Files

When a Ghidra project is opened, Ghidra creates two lock files in the project directory:

- `<projectName>.lock` - Main lock file
- `<projectName>.lock~` - Backup lock file

These files prevent other processes (including other ReVa CLI instances) from opening the same project.

### Why Locking Exists

Ghidra enforces single-process access to prevent:
- **Data corruption** from concurrent writes
- **Transaction conflicts** when multiple processes modify the same project
- **Database inconsistencies** from simultaneous updates

## ReVa's Behavior

**ReVa does NOT create locks** - it uses Ghidra's standard APIs (`GhidraProject.openProject()`), which automatically create lock files.

### Within the Same Process

If you try to open a project that's already open in the **same JVM process**, ReVa will:
- Detect that the active project matches the requested one
- Reuse the existing project instance (no error)

This works because `ProjectUtil.handleLockedProject()` checks `AppInfo.getActiveProject()`.

### Across Different Processes

If you try to open a project that's open in a **different process** (another ReVa CLI instance, Ghidra GUI, etc.), you'll get a `LockException` because:
- Each process has its own JVM
- Lock files are checked at the filesystem level
- Ghidra blocks the second open attempt

## Solutions for Shared Access

### Option 1: Ghidra Server (Recommended)

For true simultaneous access to shared projects, use **Ghidra Server**:

1. Set up a Ghidra Server instance
2. Create a shared project on the server
3. Connect multiple clients to the server project
4. Each client can access the project simultaneously

**Benefits:**
- ✅ True simultaneous access
- ✅ Proper transaction management
- ✅ No data corruption risk
- ✅ Built-in version control

**ReVa Support:**
- ReVa supports shared projects via authentication parameters
- See `docs/SHARED_PROJECT_AUTHENTICATION.md` for details

### Option 2: Workaround - Force Ignore Lock (RISKY)

You can set `REVA_FORCE_IGNORE_LOCK=true` to delete lock files before opening:

```bash
# Windows PowerShell
$env:REVA_FORCE_IGNORE_LOCK = "true"
mcp-reva

# Linux/Mac
export REVA_FORCE_IGNORE_LOCK=true
mcp-reva
```

**⚠️ WARNING: This is dangerous!**

- **Data corruption risk**: If multiple processes write simultaneously, you can corrupt the project database
- **Transaction conflicts**: Ghidra's transaction system isn't designed for concurrent access
- **No guarantees**: Project state may become inconsistent

**Only use this if:**
- You're certain only one process will write at a time
- You're okay with potential data loss
- You have backups

### Option 3: Single Process Access (Default)

The safest approach is to accept that only one process can open a project at a time:

- Close other processes before opening
- Use separate projects for different workflows
- Use Ghidra Server for true shared access

## Error Messages

When a project is locked, you'll see an error like:

```
Project 'Odyssey' is locked and cannot be opened.
Ghidra projects can only be opened by one process at a time to prevent data corruption.
The project may be open in another Ghidra instance or ReVa CLI process.

Options:
1. Close the project in the other process (Ghidra GUI or another ReVa CLI instance)
2. For shared projects: Use Ghidra Server for true simultaneous access (recommended)
3. Workaround: Set REVA_FORCE_IGNORE_LOCK=true (RISKY - can cause data corruption if multiple processes write simultaneously)

Note: ReVa does not create locks - this is Ghidra's built-in protection mechanism.
```

## Technical Details

### Lock File Location

Lock files are created in the project directory:
```
<projectDir>/
  <projectName>.lock
  <projectName>.lock~
  <projectName>.gpr
  <projectName>/
    (project data)
```

### Lock File Deletion

When `REVA_FORCE_IGNORE_LOCK=true` is set, ReVa attempts to delete lock files using:

1. **Direct deletion**: `File.delete()`
2. **Rename trick**: If direct deletion fails (file handle in use), rename the file first, then delete

This is handled by:
- `ProjectUtil.deleteLockFiles()` (Java)
- `ProjectManager._delete_lock_files()` (Python)

### Active Project Detection

ReVa checks if a locked project is already the active project:

```java
Project activeProject = AppInfo.getActiveProject();
if (activeProject != null && matches(requestedProject)) {
    // Reuse active project - no error
    return new ProjectOpenResult(activeProject, null, true, false);
}
```

This only works within the same JVM process.

## Summary

- **Locking is Ghidra's feature**, not ReVa's
- **Single-process access** is enforced to prevent corruption
- **Ghidra Server** is the proper solution for shared access
- **REVA_FORCE_IGNORE_LOCK** is a risky workaround
- **Error messages** now explain the situation and options
