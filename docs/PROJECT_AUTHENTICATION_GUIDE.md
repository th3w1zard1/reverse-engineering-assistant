# Ghidra Project Authentication Implementation Guide

## Understanding the Problem

When opening a **shared Ghidra project** (connected to a Ghidra Server), authentication is required. The current `open` tool in `ProjectToolProvider` doesn't handle authentication, which means:

1. **Local projects** (`.gpr` files on disk) - ✅ Work fine, no authentication needed
2. **Shared projects** (`.gpr` files connected to Ghidra Server) - ❌ Fail silently or prompt for credentials in GUI mode

## How Ghidra Authentication Works

### Key Concepts

1. **ClientAuthenticator Interface**: Ghidra uses a global authenticator to handle all server connections
2. **PasswordClientAuthenticator**: Implementation for username/password authentication
3. **ClientUtil.setClientAuthenticator()**: Sets the authenticator globally (must be called BEFORE opening projects)
4. **Project Types**:
   - **Local Project**: Stored on disk, no server connection needed
   - **Shared Project**: Connected to Ghidra Server, requires authentication

### Authentication Flow

```
1. User calls 'open' tool with .gpr file path
2. Check if project is shared (connected to server)
3. If shared AND credentials provided:
   - Set ClientAuthenticator using ClientUtil.setClientAuthenticator()
   - Open project (GhidraProject.openProject() will use the authenticator)
4. If shared AND no credentials:
   - Return error asking for credentials
5. If local:
   - Open project normally (no authentication needed)
```

## Step-by-Step Implementation

### Step 1: Add Authentication Parameters to Tool Schema

Add optional parameters to the `open` tool for shared project authentication:

```java
// In registerOpenTool() method, add these properties:
properties.put("serverUsername", SchemaUtil.stringProperty(
    "For shared projects: Username for Ghidra Server authentication (required for shared projects)"
));
properties.put("serverPassword", SchemaUtil.stringProperty(
    "For shared projects: Password for Ghidra Server authentication (required for shared projects)"
));
```

### Step 2: Import Required Classes

Add these imports to `ProjectToolProvider.java`:

```java
import ghidra.framework.client.ClientAuthenticator;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.PasswordClientAuthenticator;
```

### Step 3: Modify handleOpenProject() Method

Update the `handleOpenProject()` method to:

1. Check if credentials are provided
2. Set the authenticator BEFORE opening the project
3. Handle authentication errors gracefully

```java
private Map<String, Object> handleOpenProject(Map<String, Object> request, String projectPath, ToolLogCollector logCollector) {
    try {
        // Get optional authentication parameters
        String serverUsername = getOptionalString(request, "serverUsername", null);
        String serverPassword = getOptionalString(request, "serverPassword", null);
        
        // Check if this is a shared project (we'll detect this after opening)
        // For now, if credentials are provided, set up authentication
        if (serverUsername != null && serverPassword != null) {
            // Set up password-based authentication
            ClientAuthenticator authenticator = new PasswordClientAuthenticator(serverUsername, serverPassword);
            ClientUtil.setClientAuthenticator(authenticator);
            logCollector.addLog("INFO", "Authentication configured for shared project");
        }
        
        // ... rest of existing code ...
        
        // After opening project, check if it's shared and if connection succeeded
        // This would require checking Project.getRepositoryAdapter() or similar
        
    } catch (Exception e) {
        // Handle authentication errors
        if (e.getMessage() != null && e.getMessage().contains("authentication")) {
            return createErrorResult("Authentication failed: " + e.getMessage() + 
                ". Please check your username and password.");
        }
        // ... other error handling ...
    }
}
```

### Step 4: Detect Shared Projects

After opening a project, check if it's a shared project:

```java
// After GhidraProject.openProject() succeeds:
Project project = ghidraProject.getProject();

// Check if project is connected to a server
boolean isShared = project.getRepositoryAdapter() != null;
if (isShared) {
    boolean isConnected = project.getRepositoryAdapter().isConnected();
    if (!isConnected && (serverUsername == null || serverPassword == null)) {
        return createErrorResult(
            "Shared project requires authentication. " +
            "Please provide 'serverUsername' and 'serverPassword' parameters."
        );
    }
}
```

### Step 5: Handle Authentication Errors

Ghidra may throw exceptions during authentication. Handle them:

```java
try {
    ghidraProject = GhidraProject.openProject(projectDir, projectName, true);
} catch (Exception e) {
    String errorMsg = e.getMessage();
    if (errorMsg != null && (
        errorMsg.contains("authentication") ||
        errorMsg.contains("password") ||
        errorMsg.contains("login") ||
        errorMsg.contains("unauthorized")
    )) {
        return createErrorResult(
            "Authentication failed for shared project. " +
            "Error: " + errorMsg + ". " +
            "Please verify your username and password are correct."
        );
    }
    // Re-throw other exceptions
    throw e;
}
```

## Complete Implementation Example

Here's a complete example of the modified `handleOpenProject()` method:

```java
private Map<String, Object> handleOpenProject(Map<String, Object> request, String projectPath, ToolLogCollector logCollector) {
    try {
        boolean shouldOpenAllPrograms = getOptionalBoolean(request, "openAllPrograms", true);
        
        // Get optional authentication parameters
        String serverUsername = getOptionalString(request, "serverUsername", null);
        String serverPassword = getOptionalString(request, "serverPassword", null);
        
        // Validate the project file exists
        File projectFile = new File(projectPath);
        if (!projectFile.exists()) {
            logCollector.stop();
            return createErrorResult("Project file does not exist: " + projectPath);
        }
        
        // Check if it's a .gpr file
        if (!projectPath.toLowerCase().endsWith(".gpr")) {
            logCollector.stop();
            return createErrorResult("Project file must have .gpr extension: " + projectPath);
        }
        
        // Extract project directory and name
        String projectDir = projectFile.getParent();
        String projectName = projectFile.getName();
        if (projectName.toLowerCase().endsWith(".gpr")) {
            projectName = projectName.substring(0, projectName.length() - 4);
        }
        
        if (projectDir == null) {
            return createErrorResult("Invalid project path: " + projectPath);
        }
        
        // Set up authentication if credentials provided
        // This must be done BEFORE opening the project
        if (serverUsername != null && serverPassword != null) {
            try {
                ClientAuthenticator authenticator = new PasswordClientAuthenticator(serverUsername, serverPassword);
                ClientUtil.setClientAuthenticator(authenticator);
                logCollector.addLog("INFO", "Authentication configured for shared project: " + serverUsername);
            } catch (Exception e) {
                logCollector.stop();
                return createErrorResult("Failed to configure authentication: " + e.getMessage());
            }
        }
        
        // Create ProjectLocator
        ProjectLocator locator = new ProjectLocator(projectDir, projectName);
        
        // Verify the project exists
        if (!locator.getMarkerFile().exists() || !locator.getProjectDir().exists()) {
            return createErrorResult("Project not found at: " + projectPath);
        }
        
        // Try to open the project
        Project project = AppInfo.getActiveProject();
        boolean projectWasAlreadyOpen = false;
        GhidraProject ghidraProject = null;
        
        try {
            ghidraProject = GhidraProject.openProject(projectDir, projectName, true);
            project = ghidraProject.getProject();
            
            // Check if this is a shared project
            boolean isShared = project.getRepositoryAdapter() != null;
            if (isShared) {
                boolean isConnected = project.getRepositoryAdapter().isConnected();
                if (!isConnected) {
                    if (serverUsername == null || serverPassword == null) {
                        logCollector.stop();
                        return createErrorResult(
                            "Shared project requires authentication but no credentials provided. " +
                            "Please provide 'serverUsername' and 'serverPassword' parameters."
                        );
                    } else {
                        logCollector.addLog("WARN", 
                            "Shared project opened but server connection failed. " +
                            "You may need to check credentials or server availability.");
                    }
                } else {
                    logCollector.addLog("INFO", "Successfully connected to shared project server");
                }
            }
            
            // ... rest of existing code for opening programs ...
            
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            if (errorMsg != null && (
                errorMsg.contains("authentication") ||
                errorMsg.contains("password") ||
                errorMsg.contains("login") ||
                errorMsg.contains("unauthorized") ||
                errorMsg.contains("Access denied")
            )) {
                logCollector.stop();
                return createErrorResult(
                    "Authentication failed for shared project. " +
                    "Error: " + errorMsg + ". " +
                    "Please verify your username and password are correct."
                );
            }
            // Handle other errors (locked project, etc.)
            // ... existing error handling ...
        }
        
        // ... rest of method ...
        
    } catch (Exception e) {
        logCollector.stop();
        return createErrorResult("Failed to open project: " + e.getMessage());
    }
}
```

## Important Notes

### Security Considerations

1. **Password Storage**: Never log passwords or include them in error messages
2. **Password Transmission**: Passwords are sent over the network to the Ghidra Server
3. **Credential Validation**: Validate credentials are provided when needed, but don't store them

### When Authentication is Needed

- ✅ **Shared projects** (connected to Ghidra Server) - Authentication required
- ❌ **Local projects** (stored on disk) - No authentication needed
- ⚠️ **Mixed projects** - Some files may be shared, some local

### Testing

1. **Test with local project**: Should work without credentials
2. **Test with shared project + credentials**: Should authenticate and connect
3. **Test with shared project - no credentials**: Should return helpful error
4. **Test with wrong credentials**: Should return authentication error

## API Reference

### Key Classes

- `ghidra.framework.client.ClientAuthenticator` - Interface for authentication
- `ghidra.framework.client.PasswordClientAuthenticator` - Username/password implementation
- `ghidra.framework.client.ClientUtil` - Utility class for setting authenticator
- `ghidra.base.project.GhidraProject` - Project opening class
- `ghidra.framework.model.Project` - Project interface (has `getRepositoryAdapter()`)

### Key Methods

```java
// Set global authenticator (must be called before opening projects)
ClientUtil.setClientAuthenticator(ClientAuthenticator authenticator);

// Create password authenticator
new PasswordClientAuthenticator(String username, String password);

// Check if project is shared
Project.getRepositoryAdapter() != null;

// Check if shared project is connected
Project.getRepositoryAdapter().isConnected();
```

## Next Steps

1. Implement the authentication parameters in the tool schema
2. Add the authentication setup code before opening projects
3. Add error handling for authentication failures
4. Test with both local and shared projects
5. Update documentation to explain when credentials are needed
