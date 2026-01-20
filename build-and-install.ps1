# ReVa Build and Install Script
# Builds the Ghidra extension and installs it to the Ghidra extensions directory

param(
    [string]$ProjectDir = "G:\GitHub\reverse-engineering-assistant",
    [string]$GhidraInstallDir = "",
    [string]$GradlePath = ""
)

# Clear screen
Clear-Host

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
    Expand-Archive -Path $zipFile.FullName -DestinationPath $extDir -Force
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
