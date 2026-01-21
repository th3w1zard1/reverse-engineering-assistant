# ReVa Build and Install Script
# Builds the Ghidra extension and installs it to the Ghidra extensions directory

param(
    [string]$ProjectDir = "G:\GitHub\reverse-engineering-assistant",
    [string]$GhidraInstallDir = "",
    [string]$GradlePath = "",
    [Alias('f')]
    [switch]$ForceKillLocks
)

# Clear screen
Clear-Host

# Windows Restart Manager wrapper (used to find locking PIDs)
function Ensure-RestartManagerTypeLoaded {
    if ("Reva.RestartManager" -as [type]) {
        return
    }

    $typeDef = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Reva {
  public static class RestartManager {
    public const int CCH_RM_SESSION_KEY = 32;
    public const int CCH_RM_MAX_APP_NAME = 255;
    public const int CCH_RM_MAX_SVC_NAME = 63;
    public const int ERROR_MORE_DATA = 234;

    public enum RM_APP_TYPE {
      RmUnknownApp = 0,
      RmMainWindow = 1,
      RmOtherWindow = 2,
      RmService = 3,
      RmExplorer = 4,
      RmConsole = 5,
      RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILETIME {
      public uint dwLowDateTime;
      public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS {
      public int dwProcessId;
      public FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO {
      public RM_UNIQUE_PROCESS Process;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
      public string strAppName;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
      public string strServiceShortName;
      public RM_APP_TYPE ApplicationType;
      public uint AppStatus;
      public uint TSSessionId;
      [MarshalAs(UnmanagedType.Bool)]
      public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmRegisterResources(uint pSessionHandle,
      uint nFiles,
      string[] rgsFilenames,
      uint nApplications,
      IntPtr rgApplications,
      uint nServices,
      string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmGetList(uint dwSessionHandle,
      out uint pnProcInfoNeeded,
      ref uint pnProcInfo,
      [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
      ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    public static extern int RmEndSession(uint pSessionHandle);

    public static RM_PROCESS_INFO[] GetLockingProcesses(string path) {
      uint handle;
      var key = new StringBuilder(CCH_RM_SESSION_KEY + 1);
      int rc = RmStartSession(out handle, 0, key);
      if (rc != 0) {
        throw new InvalidOperationException("RmStartSession failed with error " + rc);
      }

      try {
        string[] resources = new string[] { path };
        rc = RmRegisterResources(handle, (uint)resources.Length, resources, 0, IntPtr.Zero, 0, null);
        if (rc != 0) {
          throw new InvalidOperationException("RmRegisterResources failed with error " + rc);
        }

        uint needed = 0;
        uint count = 0;
        uint reasons = 0;
        rc = RmGetList(handle, out needed, ref count, null, ref reasons);
        if (rc == ERROR_MORE_DATA) {
          var procs = new RM_PROCESS_INFO[needed];
          count = needed;
          rc = RmGetList(handle, out needed, ref count, procs, ref reasons);
          if (rc != 0) {
            throw new InvalidOperationException("RmGetList failed with error " + rc);
          }

          if (count == procs.Length) {
            return procs;
          }

          var trimmed = new RM_PROCESS_INFO[count];
          Array.Copy(procs, trimmed, count);
          return trimmed;
        }

        if (rc != 0) {
          throw new InvalidOperationException("RmGetList failed with error " + rc);
        }

        return new RM_PROCESS_INFO[0];
      } finally {
        RmEndSession(handle);
      }
    }
  }
}
"@

    Add-Type -TypeDefinition $typeDef -Language CSharp -ErrorAction Stop | Out-Null
}

function Get-LockingProcessDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Ensure-RestartManagerTypeLoaded

    try {
        $procs = [Reva.RestartManager]::GetLockingProcesses($Path)
    } catch {
        return @()
    }

    $results = @()
    foreach ($p in $procs) {
        $processId = $p.Process.dwProcessId
        if ($processId -le 0) {
            continue
        }

        $name = $p.strAppName
        if ([string]::IsNullOrWhiteSpace($name)) {
            try {
                $name = (Get-Process -Id $processId -ErrorAction Stop).ProcessName
            } catch {
                $name = "<unknown>"
            }
        }

        $results += [PSCustomObject]@{
            ProcessId = $processId
            Name      = $name
        }
    }

    return $results | Sort-Object -Property ProcessId -Unique
}

function Invoke-TaskKill {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $taskkill = Join-Path $env:SystemRoot "System32\taskkill.exe"

    & $taskkill /PID $ProcessId /T /F 2>&1 | Out-String | ForEach-Object { $_.TrimEnd() } | Out-Null
    if ($LASTEXITCODE -eq 0) {
        return $true
    }

    # Try elevation (UAC prompt) if initial kill failed (commonly Access is denied).
    try {
        $p = Start-Process -FilePath $taskkill -ArgumentList "/PID $ProcessId /T /F" -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        return ($p.ExitCode -eq 0)
    } catch {
        return $false
    }
}

function Remove-PathWithOptionalLockKilling {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [switch]$AllowKill
    )

    if (-not (Test-Path -LiteralPath $TargetPath)) {
        return $true
    }

    $failures = @()

    # Delete files first (locks are almost always on files, not directories).
    $files = Get-ChildItem -LiteralPath $TargetPath -Recurse -Force -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $filePath = $file.FullName
        try {
            Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop
        } catch {
            $locking = Get-LockingProcessDetails -Path $filePath

            if (-not $AllowKill) {
                $failures += [PSCustomObject]@{
                    Path        = $filePath
                    Error       = $_.Exception.Message
                    LockingPids = ($locking | ForEach-Object { "$($_.ProcessId) ($($_.Name))" }) -join ", "
                    KillTried   = $false
                    KillOk      = $false
                }
                continue
            }

            $killedAll = $true
            foreach ($lp in $locking) {
                if (-not (Invoke-TaskKill -ProcessId $lp.ProcessId)) {
                    $killedAll = $false
                }
            }

            try {
                Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop
            } catch {
                $failures += [PSCustomObject]@{
                    Path        = $filePath
                    Error       = $_.Exception.Message
                    LockingPids = ($locking | ForEach-Object { "$($_.ProcessId) ($($_.Name))" }) -join ", "
                    KillTried   = $true
                    KillOk      = $killedAll
                }
            }
        }
    }

    # Then delete directories bottom-up.
    $dirs = Get-ChildItem -LiteralPath $TargetPath -Recurse -Force -Directory -ErrorAction SilentlyContinue |
        Sort-Object -Property FullName -Descending
    foreach ($dir in $dirs) {
        try {
            Remove-Item -LiteralPath $dir.FullName -Force -ErrorAction Stop
        } catch {
            # If a directory won't delete, it's usually because a file is still present/locked.
            $failures += [PSCustomObject]@{
                Path        = $dir.FullName
                Error       = $_.Exception.Message
                LockingPids = ""
                KillTried   = $false
                KillOk      = $false
            }
        }
    }

    # Finally delete the root directory.
    try {
        Remove-Item -LiteralPath $TargetPath -Recurse -Force -ErrorAction Stop
    } catch {
        $failures += [PSCustomObject]@{
            Path        = $TargetPath
            Error       = $_.Exception.Message
            LockingPids = ""
            KillTried   = $false
            KillOk      = $false
        }
    }

    if ($failures.Count -gt 0) {
        Write-Host ""
        Write-Host "Failed to remove existing extension files." -ForegroundColor Red
        foreach ($f in $failures) {
            Write-Host "" -ForegroundColor Red
            Write-Host "Path: $($f.Path)" -ForegroundColor Red
            Write-Host "Error: $($f.Error)" -ForegroundColor Red
            if (-not [string]::IsNullOrWhiteSpace($f.LockingPids)) {
                Write-Host "Locking PIDs: $($f.LockingPids)" -ForegroundColor Yellow
            }
            if ($f.KillTried) {
                if ($f.KillOk) {
                    Write-Host "Tried to kill locking processes: yes (some/all succeeded), but delete still failed." -ForegroundColor Yellow
                } else {
                    Write-Host "Tried to kill locking processes: yes, but one or more kills failed (permissions/UAC denied?)." -ForegroundColor Yellow
                }
            }
        }

        if (-not $AllowKill) {
            Write-Host "" -ForegroundColor Yellow
            Write-Host "Tip: Re-run with -f to automatically taskkill the locking PIDs (will prompt for UAC if needed)." -ForegroundColor Yellow
        }

        return $false
    }

    return $true
}

# Function to load .env file from current working directory
function LoadEnvFile {
    param(
        [string]$EnvPath = ".env"
    )

    $envVars = @{}

    if (Test-Path -Path $EnvPath -PathType Leaf) {
        Write-Host "Loading .env file from: $(Resolve-Path $EnvPath)" -ForegroundColor Cyan
        $lines = Get-Content -Path $EnvPath -ErrorAction SilentlyContinue

        foreach ($line in $lines) {
            # Skip empty lines and comments
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) {
                continue
            }

            # Parse KEY=VALUE format
            if ($trimmed -match '^([^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()

                # Remove quotes if present
                if ($value.StartsWith('"') -and $value.EndsWith('"')) {
                    $value = $value.Substring(1, $value.Length - 2)
                } elseif ($value.StartsWith("'") -and $value.EndsWith("'")) {
                    $value = $value.Substring(1, $value.Length - 2)
                }

                $envVars[$key] = $value
            }
        }
    }

    return $envVars
}

# Load .env file from current directory first (as fallback)
$envVars = LoadEnvFile -EnvPath (Join-Path (Get-Location).Path ".env")

# Function to prompt for path if not provided
function Get-PathInput {
    param(
        [string]$Prompt,
        [string]$DefaultValue = "",
        [string]$Description = ""
    )

    if ($Description) {
        Write-Host $Description -ForegroundColor Cyan
    }

    if ($DefaultValue) {
        $inp = Read-Host "$Prompt [$DefaultValue]"
        if ([string]::IsNullOrWhiteSpace($inp)) {
            return $DefaultValue
        }
        return $inp
    } else {
        do {
            $inp = Read-Host $Prompt
            if ([string]::IsNullOrWhiteSpace($inp)) {
                Write-Host "Path cannot be empty. Please try again." -ForegroundColor Yellow
            }
        } while ([string]::IsNullOrWhiteSpace($inp))
        return $inp
    }
}

# Function to validate path exists
function Test-PathExists {
    param(
        [string]$Path,
        [string]$PathType = "Directory"
    )

    if ($PathType -eq "Directory") {
        if (-not (Test-Path -Path $Path -PathType Container)) {
            Write-Host "Error: Directory does not exist: $Path" -ForegroundColor Red
            return $false
        }
    } else {
        if (-not (Test-Path -Path $Path -PathType Leaf)) {
            Write-Host "Error: File does not exist: $Path" -ForegroundColor Red
            return $false
        }
    }
    return $true
}

Write-Host "=== ReVa Build and Install Script ===" -ForegroundColor Green
Write-Host ""

# Get project directory
if (-not (Test-Path -Path $ProjectDir -PathType Container)) {
    Write-Host "Project directory not found: $ProjectDir" -ForegroundColor Yellow
    $ProjectDir = Get-PathInput -Prompt "Enter project directory path" -Description "Enter the full path to the reverse-engineering-assistant project directory"
}

if (-not (Test-PathExists -Path $ProjectDir)) {
    Write-Host "Exiting: Invalid project directory" -ForegroundColor Red
    exit 1
}

# Load .env file from project directory (overrides current directory values)
$projectEnvFile = Join-Path $ProjectDir ".env"
$projectEnvVars = LoadEnvFile -EnvPath $projectEnvFile
if ($projectEnvVars.Count -gt 0) {
    # Merge project .env values (takes precedence)
    foreach ($key in $projectEnvVars.Keys) {
        $envVars[$key] = $projectEnvVars[$key]
    }
}

# Get Ghidra installation directory
if ([string]::IsNullOrWhiteSpace($GhidraInstallDir)) {
    # Check .env file first
    if ($envVars.ContainsKey("GHIDRA_INSTALL_DIR")) {
        $GhidraInstallDir = $envVars["GHIDRA_INSTALL_DIR"]
        Write-Host "Using GHIDRA_INSTALL_DIR from .env: $GhidraInstallDir" -ForegroundColor Cyan
    } else {
        $GhidraInstallDir = Get-PathInput -Prompt "Enter Ghidra installation directory" -Description "Enter the full path to your Ghidra installation directory (e.g., C:\Users\username\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC)"
    }
}

if (-not (Test-PathExists -Path $GhidraInstallDir)) {
    Write-Host "Exiting: Invalid Ghidra installation directory" -ForegroundColor Red
    exit 1
}

# Get Gradle path
if ([string]::IsNullOrWhiteSpace($GradlePath)) {
    # Check .env file first
    if ($envVars.ContainsKey("GRADLE_PATH")) {
        $GradlePath = $envVars["GRADLE_PATH"]
        Write-Host "Using GRADLE_PATH from .env: $GradlePath" -ForegroundColor Cyan
    } else {
        # Try to find gradle in common locations
        $commonGradlePaths = @(
            "C:\Gradle\gradle-8.10.2\bin\gradle.bat",
            "C:\Program Files\Gradle\gradle-8.10.2\bin\gradle.bat",
            "$env:USERPROFILE\.gradle\wrapper\dists\gradle-*\*\gradle-*\bin\gradle.bat"
        )

        $foundGradle = $null
        foreach ($path in $commonGradlePaths) {
            if ($path -like "*\*") {
                # Handle wildcard paths
                $matchingItems = Get-ChildItem -Path (Split-Path $path -Parent) -Filter (Split-Path $path -Leaf) -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($matchingItems) {
                    $foundGradle = $matchingItems.FullName
                    break
                }
            } elseif (Test-Path -Path $path -PathType Leaf) {
                $foundGradle = $path
                break
            }
        }

        $GradlePath = Get-PathInput -Prompt "Enter Gradle executable path" -DefaultValue $foundGradle -Description "Enter the full path to gradle.bat (e.g., C:\Gradle\gradle-8.10.2\bin\gradle.bat)"
    }
}

if (-not (Test-PathExists -Path $GradlePath -PathType "File")) {
    Write-Host "Exiting: Invalid Gradle executable path" -ForegroundColor Red
    exit 1
}

# Set Ghidra installation directory as environment variable
$env:GHIDRA_INSTALL_DIR = $GhidraInstallDir
Write-Host ""
Write-Host "Set GHIDRA_INSTALL_DIR = $GhidraInstallDir" -ForegroundColor Cyan

# Change to project directory
Write-Host ""
Write-Host "Changing to project directory: $ProjectDir" -ForegroundColor Cyan
Set-Location $ProjectDir

# Build the extension
Write-Host ""
Write-Host "Building extension with Gradle..." -ForegroundColor Cyan
Write-Host "Command: $GradlePath buildExtension --info" -ForegroundColor Gray
Write-Host ""

try {
    & $GradlePath buildExtension --info
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "Build failed with exit code $LASTEXITCODE" -ForegroundColor Red
        exit $LASTEXITCODE
    }
} catch {
    Write-Host ""
    Write-Host "Error running Gradle: $_" -ForegroundColor Red
    exit 1
}

# Find the latest zip file in dist directory
Write-Host ""
Write-Host "Looking for extension zip file in dist directory..." -ForegroundColor Cyan
$distDir = Join-Path $ProjectDir "dist"
if (-not (Test-Path -Path $distDir -PathType Container)) {
    Write-Host "Error: dist directory not found: $distDir" -ForegroundColor Red
    exit 1
}

$zipFile = Get-ChildItem -Path $distDir -Filter "*reverse-engineering-assistant.zip" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $zipFile) {
    Write-Host "Error: No extension zip file found in dist directory" -ForegroundColor Red
    exit 1
}

Write-Host "Found zip file: $($zipFile.Name) (Last modified: $($zipFile.LastWriteTime))" -ForegroundColor Green

# Determine extensions directory
# Check .env file first, otherwise derive from Ghidra install directory
if ($envVars.ContainsKey("GHIDRA_EXTENSIONS_DIR")) {
    $extDir = $envVars["GHIDRA_EXTENSIONS_DIR"]
    Write-Host "Using GHIDRA_EXTENSIONS_DIR from .env: $extDir" -ForegroundColor Cyan
} else {
    $extDir = Join-Path $GhidraInstallDir "Ghidra\Extensions"
}

if (-not (Test-Path -Path $extDir -PathType Container)) {
    Write-Host "Warning: Extensions directory does not exist, creating: $extDir" -ForegroundColor Yellow
    New-Item -Path $extDir -ItemType Directory -Force | Out-Null
}

# Expand archive
Write-Host ""
Write-Host "Installing extension to: $extDir" -ForegroundColor Cyan
try {
    $extensionFolderName = "reverse-engineering-assistant"
    $existingExtensionDir = Join-Path $extDir $extensionFolderName

    if (Test-Path -LiteralPath $existingExtensionDir -PathType Container) {
        Write-Host "Existing extension detected at: $existingExtensionDir" -ForegroundColor Yellow
        Write-Host "Removing existing extension (locks may require closing Ghidra)..." -ForegroundColor Cyan

        $removedOk = Remove-PathWithOptionalLockKilling -TargetPath $existingExtensionDir -AllowKill:$ForceKillLocks
        if (-not $removedOk) {
            Write-Host ""
            Write-Host "Install aborted: could not remove the existing extension." -ForegroundColor Red
            exit 1
        }
    }

    Expand-Archive -Path $zipFile.FullName -DestinationPath $extDir -Force -ErrorAction Stop

    $installedDir = Join-Path $extDir $extensionFolderName
    if (-not (Test-Path -LiteralPath $installedDir -PathType Container)) {
        throw "Install did not produce expected folder: $installedDir"
    }

    Write-Host ""
    Write-Host "=== Extension installed successfully! ===" -ForegroundColor Green
    Write-Host "Extension installed to: $extDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now restart Ghidra to use the extension." -ForegroundColor Cyan
} catch {
    Write-Host ""
    Write-Host "Error installing extension: $_" -ForegroundColor Red
    exit 1
}
