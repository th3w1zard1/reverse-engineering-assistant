# PowerShell script to run all ReVa tests
# Attempts to find Ghidra automatically, or uses provided path

param(
    [string]$GhidraPath = ""
)

# Function to find Ghidra installation
function Find-GhidraInstall {
    $commonPaths = @(
        "C:\Program Files\Ghidra",
        "C:\ghidra",
        "$env:USERPROFILE\ghidra",
        "$env:USERPROFILE\Desktop\ghidra",
        "$env:USERPROFILE\Downloads\ghidra",
        "C:\Program Files (x86)\Ghidra"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            # Check if it looks like a Ghidra installation
            if (Test-Path (Join-Path $path "support\buildExtension.gradle")) {
                Write-Host "Found Ghidra at: $path"
                return $path
            }
        }
    }
    
    return $null
}

# Set GHIDRA_INSTALL_DIR
if ($GhidraPath -ne "") {
    $env:GHIDRA_INSTALL_DIR = $GhidraPath
    Write-Host "Using provided Ghidra path: $GhidraPath"
} else {
    $foundPath = Find-GhidraInstall
    if ($foundPath) {
        $env:GHIDRA_INSTALL_DIR = $foundPath
        Write-Host "Using auto-detected Ghidra path: $foundPath"
    } else {
        Write-Host "ERROR: Could not find Ghidra installation."
        Write-Host "Please provide the path: .\run-all-tests.ps1 -GhidraPath 'C:\path\to\ghidra'"
        Write-Host ""
        Write-Host "Or set GHIDRA_INSTALL_DIR environment variable:"
        Write-Host "  `$env:GHIDRA_INSTALL_DIR = 'C:\path\to\ghidra'"
        exit 1
    }
}

# Verify Ghidra path
if (-not (Test-Path $env:GHIDRA_INSTALL_DIR)) {
    Write-Host "ERROR: Ghidra path does not exist: $env:GHIDRA_INSTALL_DIR"
    exit 1
}

if (-not (Test-Path (Join-Path $env:GHIDRA_INSTALL_DIR "support\buildExtension.gradle"))) {
    Write-Host "ERROR: Path does not appear to be a valid Ghidra installation: $env:GHIDRA_INSTALL_DIR"
    exit 1
}

Write-Host ""
Write-Host "=========================================="
Write-Host "Running ReVa Test Suite"
Write-Host "GHIDRA_INSTALL_DIR: $env:GHIDRA_INSTALL_DIR"
Write-Host "=========================================="
Write-Host ""

# Run unit tests
Write-Host "Step 1: Running unit tests..."
Write-Host "----------------------------------------"
gradle test --info
$unitTestExitCode = $LASTEXITCODE

if ($unitTestExitCode -ne 0) {
    Write-Host ""
    Write-Host "WARNING: Unit tests failed with exit code $unitTestExitCode"
    Write-Host "Continuing with integration tests..."
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "✓ Unit tests passed!"
    Write-Host ""
}

# Run integration tests
Write-Host "Step 2: Running integration tests..."
Write-Host "----------------------------------------"
gradle integrationTest --info
$integrationTestExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "=========================================="
Write-Host "Test Execution Complete"
Write-Host "=========================================="
Write-Host "Unit Tests Exit Code: $unitTestExitCode"
Write-Host "Integration Tests Exit Code: $integrationTestExitCode"
Write-Host ""

if ($unitTestExitCode -eq 0 -and $integrationTestExitCode -eq 0) {
    Write-Host "✓ All tests passed!"
    exit 0
} else {
    Write-Host "✗ Some tests failed. Review output above for details."
    exit 1
}
