# Shared Project Authentication

ReVa now supports authentication for shared Ghidra projects (projects connected to a Ghidra Server). This allows you to open remote projects that require username/password authentication.

## Overview

When opening a `.gpr` file that is connected to a Ghidra Server, authentication may be required. ReVa supports providing credentials and server address information in two ways:

1. **Tool Parameters**: Pass `serverUsername`, `serverPassword`, `serverHost`, and `serverPort` directly to the `open` tool
2. **Environment Variables**: Set `REVA_SERVER_USERNAME`, `REVA_SERVER_PASSWORD`, `REVA_SERVER_HOST`, and `REVA_SERVER_PORT` environment variables

**Important Note**: The server host and port are typically stored in the project file (`.gpr`) when the project is created. The `serverHost` and `serverPort` parameters are provided for reference and documentation purposes. Ghidra will use the server address stored in the project file when connecting. If the server has moved, you may need to reconfigure the project in Ghidra's GUI.

## Usage

### Method 1: Tool Parameters

```json
{
  "tool": "open",
  "arguments": {
    "path": "G:/Projects/Odyssey.gpr",
    "serverUsername": "myuser",
    "serverPassword": "mypassword",
    "serverHost": "ghidra.example.com",
    "serverPort": 13100,
    "openAllPrograms": true
  }
}
```

**Note**: `serverHost` and `serverPort` are optional and provided for reference. The actual server address is stored in the project file and will be used by Ghidra.

### Method 2: Environment Variables

Set environment variables before starting the MCP server:

**Windows (PowerShell):**
```powershell
$env:REVA_SERVER_USERNAME = "myuser"
$env:REVA_SERVER_PASSWORD = "mypassword"
```

**Linux/Mac (Bash):**
```bash
export REVA_SERVER_USERNAME="myuser"
export REVA_SERVER_PASSWORD="mypassword"
```

**MCP Server Configuration (JSON):**
```json
{
  "mcpServers": {
    "reva": {
      "command": "uv",
      "args": [
        "--project",
        "G:/GitHub/Andastra/.cursor/mcp/reverse-engineering-assistant",
        "run",
        "--module",
        "reva_cli"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "C:/Users/boden/Downloads/ghidra_12.0_PUBLIC_20251205/ghidra_12.0_PUBLIC",
        "REVA_PROJECT_PATH": "G:/GitHub/Andastra/Odyssey.gpr",
        "REVA_SERVER_USERNAME": "myuser",
        "REVA_SERVER_PASSWORD": "mypassword",
        "REVA_SERVER_HOST": "ghidra.example.com",
        "REVA_SERVER_PORT": "13100"
      }
    }
  }
}
```

**Note**: `REVA_SERVER_HOST` and `REVA_SERVER_PORT` are optional. The server address is typically stored in the project file and will be used automatically.

### Method 3: Combined (Parameters Override Environment Variables)

If both are provided, tool parameters take precedence:

```json
{
  "tool": "open",
  "arguments": {
    "path": "G:/Projects/Odyssey.gpr",
    "serverUsername": "override_user",  // This overrides REVA_SERVER_USERNAME
    "serverPassword": "override_pass"   // This overrides REVA_SERVER_PASSWORD
  }
}
```

## How It Works

1. **Credential Resolution**: ReVa checks tool parameters first, then falls back to environment variables
2. **Authentication Setup**: If credentials are found, ReVa sets up `PasswordClientAuthenticator` using `ClientUtil.setClientAuthenticator()` **before** opening the project
3. **Project Opening**: Ghidra's `GhidraProject.openProject()` uses the configured authenticator automatically
4. **Connection Check**: After opening, ReVa checks if the project is shared and if the server connection succeeded

## Response Format

The `open` tool response includes authentication status and server information:

```json
{
  "success": true,
  "projectPath": "G:/Projects/Odyssey.gpr",
  "projectName": "Odyssey",
  "isShared": true,
  "serverConnected": true,
  "authenticationUsed": true,
  "serverHost": "ghidra.example.com",
  "serverPort": 13100,
  "providedServerHost": "ghidra.example.com",
  "providedServerPort": 13100,
  "programCount": 5,
  "openedPrograms": ["/program1.exe", "/program2.dll"],
  "message": "Project 'Odyssey' opened successfully. 5 programs found, 5 opened into memory, 0 failed."
}
```

### Response Fields

- `isShared`: `true` if the project is connected to a Ghidra Server
- `serverConnected`: `true` if successfully connected to the server (only present if `isShared` is `true`)
- `authenticationUsed`: `true` if credentials were provided and used (only present if `isShared` is `true`)
- `serverHost`: The actual server hostname from the project file (only present if `isShared` is `true`)
- `serverPort`: The actual server port from the project file (only present if `isShared` is `true`)
- `providedServerHost`: The server host provided via parameters/environment (only present if provided)
- `providedServerPort`: The server port provided via parameters/environment (only present if provided)

## Error Handling

### Missing Credentials for Shared Project

If a shared project requires authentication but no credentials are provided:

```json
{
  "success": false,
  "error": "Shared project requires authentication but no credentials provided. Please provide 'serverUsername' and 'serverPassword' parameters, or set REVA_SERVER_USERNAME and REVA_SERVER_PASSWORD environment variables."
}
```

### Authentication Failure

If credentials are provided but authentication fails:

```json
{
  "success": false,
  "error": "Authentication failed for shared project. Error: Invalid credentials. Please verify your username and password are correct. You can provide credentials via 'serverUsername'/'serverPassword' parameters or REVA_SERVER_USERNAME/REVA_SERVER_PASSWORD environment variables."
}
```

### Connection Failure

If authentication succeeds but the server connection fails:

The project will still open, but you'll see a warning in the logs:

```
"Shared project opened but server connection failed. Please verify credentials and server availability."
```

The response will include:
```json
{
  "isShared": true,
  "serverConnected": false,
  "authenticationUsed": true
}
```

## Security Considerations

1. **Password Storage**: 
   - Environment variables are stored in your MCP server configuration file
   - Tool parameters are sent in the MCP request (visible in logs)
   - **Never commit credentials to version control**

2. **Password Transmission**:
   - Credentials are sent over the network to the Ghidra Server
   - Use secure connections (HTTPS/TLS) when possible

3. **Best Practices**:
   - Use environment variables for persistent credentials
   - Use tool parameters for one-time operations
   - Consider using a secrets manager for production environments

## Local vs Shared Projects

### Local Projects
- Stored entirely on disk
- No server connection required
- No authentication needed
- Credentials are ignored if provided

### Shared Projects
- Connected to a Ghidra Server
- Server connection required for full functionality
- Authentication required if server requires it
- Can work offline, but version control features require connection

## Examples

### Example 1: Open Shared Project with Environment Variables

**Setup:**
```json
{
  "mcpServers": {
    "reva": {
      "env": {
        "REVA_SERVER_USERNAME": "analyst1",
        "REVA_SERVER_PASSWORD": "secure_password"
      }
    }
  }
}
```

**Tool Call:**
```json
{
  "tool": "open",
  "arguments": {
    "path": "G:/Projects/Odyssey.gpr"
  }
}
```

### Example 2: Open Shared Project with Tool Parameters

**Tool Call:**
```json
{
  "tool": "open",
  "arguments": {
    "path": "G:/Projects/Odyssey.gpr",
    "serverUsername": "analyst1",
    "serverPassword": "secure_password",
    "openAllPrograms": true
  }
}
```

### Example 3: Open Local Project (No Authentication Needed)

**Tool Call:**
```json
{
  "tool": "open",
  "arguments": {
    "path": "G:/Projects/LocalProject.gpr"
  }
}
```

Credentials are ignored for local projects.

## Troubleshooting

### "Shared project requires authentication but no credentials provided"

**Solution**: Provide credentials via tool parameters or environment variables.

### "Authentication failed for shared project"

**Possible Causes**:
- Incorrect username or password
- User account doesn't exist on the server
- Account is locked or disabled
- Server authentication method changed

**Solution**: Verify credentials with the Ghidra Server administrator.

### "Shared project opened but server connection failed"

**Possible Causes**:
- Server is offline or unreachable
- Network connectivity issues
- Firewall blocking connection
- Server port changed

**Solution**: Check server status and network connectivity.

## Implementation Details

The authentication is implemented using Ghidra's `ClientAuthenticator` interface:

1. **PasswordClientAuthenticator**: Provides username/password authentication
2. **ClientUtil.setClientAuthenticator()**: Sets the authenticator globally (must be called before opening projects)
3. **Automatic Usage**: Ghidra automatically uses the authenticator when connecting to servers

The authenticator is set **before** calling `GhidraProject.openProject()`, ensuring it's available when Ghidra attempts to connect to the server.
